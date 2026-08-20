package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/chronos/chronos-go/internal/platform/ids"
)

// Credential kinds this job knows how to re-seal.
//
// Stable strings rather than Go identifiers, because they are the `kind` column's
// discriminator: they cross into SQL, into the work list, into the log line an
// operator greps, and into workflow history. A Go rename must not change what any
// of those match.
//
// Only the two kinds that HOLD a sealed value appear here. `recovery_code` and
// `passkey` never match the work list — a recovery code is digested and a passkey
// is a public key, so both leave `verifier` NULL — and `federated` holds nothing
// of ours at all.
const (
	KindPassword = "password"
	KindTOTP     = "totp"
)

// SealedCredential is one row of the re-sealing work list.
//
// It carries the sealed value, which is CIPHERTEXT, and three identifiers, none
// of which is personal data: a credential id and a user id are prefixed ULIDs
// (ADR-030) and a subject id is a pseudonym (ADR-002). Nothing here may be
// widened to carry a plaintext secret, a password or an address — this type is
// counted, logged around, and its identifiers reach workflow history.
type SealedCredential struct {
	// ID is the credential's own id. Half the AES-GCM additional data for both
	// kinds, so a value re-sealed against the wrong id cannot be opened again.
	ID ids.CredentialID

	// SubjectID owns the credential. The other half of the TOTP binding.
	SubjectID string

	// UserID is the other half of the PASSWORD binding, and it is NOT on the
	// credential row — the work list reaches it through user_view. It is zero for
	// a TOTP row (which does not need it) and, importantly, also zero when the
	// projection has no row for this subject, which is a real state because
	// migration 00009 removed the foreign key that used to prevent it.
	UserID ids.UserID

	// Sealed is the stored ciphertext, verbatim. It is the compare-and-set's
	// expected value as well as the resealer's input, so it must not be
	// normalised, trimmed or re-encoded anywhere between here and the write.
	Sealed string
}

// Resealer moves one stored ciphertext from an old key version to the current
// one, WITHOUT the plaintext that produced it.
//
// That "without the plaintext" is the whole reason a batch re-seal exists at all,
// and it is worth stating plainly because it is not obvious. A password verifier
// is Argon2id(password, salt) SEALED under the pepper — not Argon2id(password ‖
// pepper). The digest is the sealed plaintext, so opening it under the old pepper
// and re-sealing it under the new one is a pure ciphertext transformation: the
// salt, the cost parameters and the digest are all preserved, and the user's
// password is never involved. The concatenated-pepper design that most systems
// use cannot do this at all — its pepper can never be changed, including after it
// leaks (see the argon2id package comment). A TOTP secret is even more direct:
// the plaintext IS the secret, and it comes back from Open.
//
// The consequence for this job is that it can repair every account, not only the
// accounts that happen to sign in. The login-time rehash path upgrades a verifier
// while the plaintext is briefly in memory, which is correct and free but reaches
// only people who log in; an account dormant since the rotation is stranded under
// a key the operator is waiting to destroy, and a TOTP secret has no login-time
// path whatsoever because no login ever recovers it in a form that could be
// re-sealed opportunistically.
//
// A Resealer NEVER invents a secret. If it cannot open the stored value it
// returns an error and the row is left exactly as it was — a job that generated a
// fresh verifier or a fresh TOTP secret on a failed open would silently lock an
// account out of a password it knows, or silently replace an authenticator the
// user still holds.
type Resealer interface {
	// Kind is the credential kind this resealer owns. It selects the work list,
	// so a resealer registered under the wrong kind would hand password verifiers
	// to the TOTP opener — which fails closed (the formats do not parse as each
	// other) but fails on every row.
	Kind() string

	// CurrentVersion is the key version Reseal produces. It is the `below` bound
	// of the work list and the value written to pepper_version, so the two cannot
	// drift. Must be >= 1: a row at 0 is invisible to `pepper_version < n`.
	CurrentVersion() int32

	// Reseal opens sealed under whichever loaded key it names and re-seals it
	// under the current key, returning the new stored form.
	//
	// It returns an error wrapping ErrVerifierUnreadable or ErrSecretUnreadable
	// when the value cannot be opened under ANY loaded key — the operationally
	// serious case, because it means the row will lose its secret when the old
	// key goes — and ErrAlreadyCurrent when the value already names the current
	// version, which is a no-op rather than a fault.
	//
	// No context parameter: the keys are held in memory (see PasswordHasher and
	// TotpSealer for why), so there is no round trip to cancel, and an unused ctx
	// is a promise of cancellability nothing behind it honours.
	Reseal(sealed string, cred SealedCredential) (string, error)
}

// ErrAlreadyCurrent means a stored value already names the current key version.
//
// It is a SKIP, not a failure. It is reachable because pepper_version is a copy
// of the version inside the verifier and the two are allowed to disagree — the
// migration says so, and says the verifier wins. Re-sealing such a row would
// produce fresh ciphertext at an unchanged version on every pass forever, which
// is the shape of a job that looks busy and finishes never.
var ErrAlreadyCurrent = errors.New("identity: the sealed value is already at the current key version")

// ResealableCredentials is the re-sealing job's store port.
//
// Read-mostly and deliberately narrow: a work list, a done check, and one
// compare-and-set. There is no unconditional update here and there must never be
// — see Reseal below.
//
// Every implementation runs in a SYSTEM transaction. Identity's tables carry no
// RLS, and a key rotation spans every tenant by nature.
type ResealableCredentials interface {
	// ListToReseal returns credentials of one kind still sealed below version,
	// ordered by credential id, starting strictly after the given cursor.
	//
	// The cursor is what makes the job resumable PAST A FAILURE. Without it a row
	// that cannot be re-sealed keeps its old version, matches again, and comes
	// back at the head of every page — one unopenable secret would pin the job to
	// the first page forever while every pass reported that it had scanned rows.
	// An empty string starts from the beginning.
	ListToReseal(
		ctx context.Context, kind string, below int32, after string, limit int,
	) ([]SealedCredential, error)

	// CountToReseal is the DONE check: how many rows of this kind are still
	// sealed below version, ignoring any cursor.
	//
	// It is a separate question from the work list and cannot be inferred from
	// it. A zero-length PAGE means only "nothing after the cursor"; it is
	// returned both when the job has finished and when everything left is behind
	// the cursor because it failed. Only this answers "is it safe to destroy the
	// old key", which is the single question the whole job exists to make
	// answerable.
	CountToReseal(ctx context.Context, kind string, below int32) (int64, error)

	// Reseal writes a new sealed value, but only if the row still holds expected
	// AND is still below version.
	//
	// Returns ErrCredentialMoved when it affects no rows. That is NOT an error
	// condition for this job: it means the login-time rehash, a password change
	// or a second-factor re-enrollment won the race, and every one of those wrote
	// a value sealed under the CURRENT key — the exact outcome being attempted.
	// Treating it as a failure would make a healthy, busy system report a broken
	// rotation.
	Reseal(
		ctx context.Context, cred ids.CredentialID, expected, replacement string, version int32,
	) error
}

// ResealPass is what one bounded pass did, for one kind.
type ResealPass struct {
	// Kind is the credential kind this pass worked on.
	Kind string

	// Version is the key version rows were moved TO.
	Version int32

	// Scanned is how many rows the work list returned.
	Scanned int

	// Resealed is how many rows this pass actually moved to the current version.
	Resealed int

	// Skipped is how many rows needed nothing: the compare-and-set found the row
	// already changed, or the stored value already named the current version.
	// Ordinary and expected on a live system, never an error.
	Skipped int

	// Unopenable is how many rows could not be opened under ANY loaded key.
	//
	// Counted apart from Failed because it is a categorically different event. A
	// transient failure is retried by the next pass and costs nothing. A value
	// that will not open is an account that LOSES ITS FACTOR the moment the old
	// key is destroyed — a password nobody can verify, or a second factor nobody
	// can complete — and the loss is unrecoverable because the plaintext exists
	// nowhere else. Almost always it means the key that sealed it is not loaded,
	// which is a configuration mistake that must be fixed BEFORE the rotation
	// proceeds, not a row to be written off.
	Unopenable int

	// Failed is how many rows could not be processed for any other reason: an
	// unreadable id, a password row with no user_view row to bind against, a
	// write that errored.
	Failed int

	// Cursor is the credential id of the LAST row scanned, or the caller's cursor
	// unchanged when the page was empty. Feeding it back is what steps the next
	// pass over rows this one could not fix.
	Cursor string

	// More reports that the page filled, so there is very likely work after the
	// cursor. It is what makes a caller loop instead of guessing.
	More bool

	// Remaining is the done check, taken AFTER the writes: rows of this kind
	// still below the current version, anywhere in the table. Zero — and only
	// zero — is what makes it safe to destroy the old key.
	Remaining int64

	// Counted reports that the done check actually RAN.
	//
	// It exists because Remaining's zero value and its "nothing left" value are
	// the same number, and that number is the one an operator acts on. A pass
	// whose COUNT failed — a statement timeout, a lost connection — would
	// otherwise carry Remaining: 0 and read as a completed rotation. "The count
	// could not be taken" and "there is nothing left" must be different answers.
	Counted bool
}

// Done reports that this kind has nothing left at an old version.
//
// It reads Counted and Remaining, and deliberately ignores Scanned, More and the
// page length. "The page came back empty" is the wrong test and is the specific
// mistake the separate count exists to prevent: an empty page is also what a job
// produces when everything left is behind its cursor because it could not be
// re-sealed.
func (p ResealPass) Done() bool { return p.Counted && p.Remaining == 0 }

// KeyReseal moves credential secrets onto the current key so a rotation can
// finish.
//
// # Why this job exists
//
// Two key sets seal values in the `credential` table: the Argon2id pepper over
// password verifiers, and the totpseal key over TOTP shared secrets. Both are
// versioned, both are wrapped by the OpenBao KEK (ADR-028), and both carry one
// operational rule that nothing in code can enforce — do not destroy an old key
// until nothing is sealed under it (identity.md §4).
//
// Before this job, nothing re-sealed anything. An operator could rotate, but the
// count of rows at the old version never fell, so the only safe action was to
// keep every old key forever — and "forever" includes after the key leaks, which
// is the one situation rotation is for. The login-time rehash path helped only
// with passwords and only for accounts that signed in; a dormant account was
// stranded, and TOTP had no equivalent path at all.
//
// # Why ONE job and not one per kind
//
// The two kinds differ in exactly two places — which key set opens the value, and
// which primitive re-seals it — and both are behind the Resealer port. Everything
// else is identical: the same table, the same `pepper_version` column, the same
// work list, the same compare-and-set, the same done check, the same "an empty
// page is not completion" trap. Splitting it would duplicate all of that, and the
// duplicate is where the two would drift: the previous bug here was a work list
// that hardcoded `kind = 'password'` and therefore could not see TOTP rows at
// all, reporting zero while every second factor still depended on the old key.
// One job that takes the kind as a parameter cannot develop a blind spot in one
// kind that the other does not have.
//
// They stay SEPARATE PASSES rather than one merged list, because the version
// sequences are unrelated: pepper v3 says nothing about totpseal v3, and one
// query spanning both would compare two independent counters.
type KeyReseal struct {
	store     ResealableCredentials
	resealers map[string]Resealer
	log       *slog.Logger
}

// NewKeyReseal builds the use case.
//
// It requires at least one resealer and refuses duplicates. A KeyReseal with no
// resealers would run every pass to completion and report success while moving
// nothing — the failure mode that makes an operator destroy a key that is still
// in use, which is the single worst outcome in this whole area.
func NewKeyReseal(
	store ResealableCredentials, log *slog.Logger, resealers ...Resealer,
) (*KeyReseal, error) {
	if store == nil {
		return nil, errors.New("identity: the re-sealing job needs a credential store; " +
			"without one every run reports success while nothing is re-sealed, and a key " +
			"rotation can never be completed")
	}
	if len(resealers) == 0 {
		return nil, errors.New("identity: the re-sealing job needs at least one resealer; " +
			"with none it would scan nothing, report a clean pass, and leave every verifier " +
			"and every TOTP secret pinned to the key an operator is trying to retire")
	}

	byKind := make(map[string]Resealer, len(resealers))
	for _, r := range resealers {
		switch {
		case r == nil:
			return nil, errors.New("identity: a nil resealer would panic on the first row " +
				"of its kind, in a job nobody is watching")
		case r.Kind() == "":
			return nil, errors.New("identity: a resealer must name the credential kind it " +
				"owns, or it selects no work list")
		case r.CurrentVersion() < 1:
			// Version 0 is the zero value of the column. A job bounded by
			// `pepper_version < 0` selects nothing and reports a clean pass.
			return nil, fmt.Errorf("identity: the %s resealer reports key version %d; a "+
				"version below 1 makes the work list select nothing and the job report "+
				"success over untouched rows", r.Kind(), r.CurrentVersion())
		}
		if _, dup := byKind[r.Kind()]; dup {
			// Two resealers for one kind means one of them is silently unused,
			// and which one wins is map-iteration order.
			return nil, fmt.Errorf("identity: two resealers claim kind %q", r.Kind())
		}
		byKind[r.Kind()] = r
	}
	if log == nil {
		log = slog.Default()
	}
	return &KeyReseal{store: store, resealers: byKind, log: log}, nil
}

// Kinds reports the credential kinds this job can re-seal, sorted.
//
// Exposed so the caller — a workflow that must be deterministic — can iterate
// them in a stable order, and so a composition-root test can assert that the
// binary wired the kinds it believes it did rather than a subset.
func (k *KeyReseal) Kinds() []string {
	out := make([]string, 0, len(k.resealers))
	for kind := range k.resealers {
		out = append(out, kind)
	}
	// Sorted so two passes of one run, and a replay of that run, visit the kinds
	// in the same order. Map order in Go is deliberately randomised, and the
	// caller is a Temporal workflow — a non-deterministic iteration order there
	// corrupts history on replay rather than merely looking untidy.
	slices.Sort(out)
	return out
}

// ResealOnce re-seals at most limit credentials of one kind, starting after a
// cursor.
//
// It returns an error only when the pass could not be ATTEMPTED — an unknown
// kind, a work list that could not be read. A single row that fails is counted
// and the batch continues: one unreadable credential must not leave every other
// account pinned to a key the operator is trying to destroy, and the row is
// visited again by a later run because its version did not move.
//
// The done check runs even when the page was empty, and that ordering is the
// point. "Nothing after the cursor" and "nothing left anywhere" are different
// facts, and only the second one licenses destroying a key.
func (k *KeyReseal) ResealOnce(
	ctx context.Context, kind, after string, limit int,
) (ResealPass, error) {
	if limit <= 0 {
		return ResealPass{}, fmt.Errorf("identity: a re-sealing limit of %d moves no rows", limit)
	}
	resealer, ok := k.resealers[kind]
	if !ok {
		// Named rather than ignored. A silently skipped kind is how TOTP secrets
		// went unseen the first time.
		return ResealPass{}, fmt.Errorf("identity: no resealer is wired for credential kind %q, "+
			"so its rows would stay at an old key version with nothing reporting it", kind)
	}
	version := resealer.CurrentVersion()

	rows, err := k.store.ListToReseal(ctx, kind, version, after, limit)
	if err != nil {
		return ResealPass{}, fmt.Errorf("identity: listing %s credentials to re-seal: %w", kind, err)
	}

	pass := ResealPass{
		Kind:    kind,
		Version: version,
		Scanned: len(rows),
		Cursor:  after,
		More:    len(rows) >= limit,
	}
	for _, row := range rows {
		// Advanced BEFORE the outcome is known, and unconditionally. The cursor
		// records where the pass looked, not what it fixed — a cursor that only
		// moved on success would stop dead at the first row that could not be
		// re-sealed.
		pass.Cursor = row.ID.String()
		k.apply(ctx, resealer, row, version, &pass)
	}

	remaining, err := k.store.CountToReseal(ctx, kind, version)
	if err != nil {
		// The writes already happened, so the pass is reported rather than
		// discarded — but the count is the only thing that can say "the rotation
		// is complete", so failing to take it must never read as zero.
		return pass, fmt.Errorf("identity: counting %s credentials still at an old key "+
			"version: %w", kind, err)
	}
	pass.Remaining, pass.Counted = remaining, true

	k.report(pass)
	return pass, nil
}

// apply re-seals one row into pass's counters.
//
// Split out so every outcome is a single, named branch. The categories are the
// job's whole output, and collapsing any two of them destroys the signal: a lost
// race counted as a failure makes a healthy system look broken, and an unopenable
// secret counted as a skip hides an account that is about to lose its factor.
func (k *KeyReseal) apply(
	ctx context.Context, resealer Resealer, row SealedCredential, version int32, pass *ResealPass,
) {
	switch {
	case row.ID.IsZero():
		pass.Failed++
		k.log.Error("a credential in the re-sealing work list has no readable id; it stays "+
			"at its old key version", "kind", pass.Kind, "subject_id", row.SubjectID)
		return
	case row.Sealed == "":
		// The work list filters `verifier IS NOT NULL`, so an empty string got
		// past a CHECK constraint. Nothing can open it and nothing should
		// overwrite it.
		pass.Failed++
		k.log.Error("a credential in the re-sealing work list holds an empty sealed value",
			"kind", pass.Kind, "credential_id", row.ID.String())
		return
	case pass.Kind == KindPassword && row.UserID.IsZero():
		// The password binding needs the user id, and the credential row does not
		// carry one. Reported rather than skipped: this means user_view has no row
		// for a subject that has a password, which is either a projection rebuild
		// in flight or a genuine inconsistency, and in both cases the row keeps
		// counting against the done check until somebody looks.
		pass.Failed++
		k.log.Error("a password credential has no user_view row, so its verifier cannot be "+
			"bound and cannot be re-sealed; it stays at its old key version and keeps the "+
			"old pepper alive",
			"credential_id", row.ID.String(), "subject_id", row.SubjectID)
		return
	}

	replacement, err := resealer.Reseal(row.Sealed, row)
	switch {
	case errors.Is(err, ErrAlreadyCurrent):
		pass.Skipped++
		return
	case errors.Is(err, ErrVerifierUnreadable), errors.Is(err, ErrSecretUnreadable):
		pass.Unopenable++
		// The loudest line this job produces, and the only one that describes a
		// loss rather than a delay. No secret, no verifier and no ciphertext in
		// it — the identifiers are pseudonyms and ULIDs (ADR-002).
		k.log.Error("A CREDENTIAL CANNOT BE OPENED UNDER ANY LOADED KEY. It will NOT be "+
			"re-sealed, and the account loses this authentication method the moment the old "+
			"key is destroyed. Load the key version this row was sealed under before "+
			"continuing the rotation",
			"kind", pass.Kind, "credential_id", row.ID.String(),
			"subject_id", row.SubjectID, "error", err)
		return
	case err != nil:
		pass.Failed++
		k.log.Error("a credential could not be re-sealed; it stays at its old key version "+
			"and is retried by the next run",
			"kind", pass.Kind, "credential_id", row.ID.String(), "error", err)
		return
	case replacement == "":
		// Refused rather than written. An empty replacement passes the store's
		// own emptiness check nowhere and would satisfy "the row was updated"
		// while destroying the only copy of the secret.
		pass.Failed++
		k.log.Error("a resealer produced an empty value; the row is left untouched",
			"kind", pass.Kind, "credential_id", row.ID.String())
		return
	case replacement == row.Sealed:
		// Byte-identical output means nothing was re-sealed: GCM's nonce is random
		// per call, so a genuine re-seal can never reproduce its input. Writing it
		// would move pepper_version onto a value the new key cannot open.
		pass.Failed++
		k.log.Error("a resealer returned the stored value unchanged; the row is left "+
			"untouched rather than stamped with a version that would not open it",
			"kind", pass.Kind, "credential_id", row.ID.String())
		return
	}

	err = k.store.Reseal(ctx, row.ID, row.Sealed, replacement, version)
	switch {
	case errors.Is(err, ErrCredentialMoved):
		// SOMEBODY ELSE WON, and that is a success for the rotation, not a
		// failure of this pass. The compare-and-set exists precisely so this
		// outcome is possible: between the read and the write, a login-time
		// rehash, a password change or a TOTP re-enrollment replaced the value
		// with one sealed under the CURRENT key. Retrying would be wrong — the
		// value we opened no longer exists — and reporting an error would make
		// every busy deployment look like a broken rotation.
		pass.Skipped++
	case err != nil:
		pass.Failed++
		k.log.Error("a re-sealed credential could not be written back; it stays at its old "+
			"key version and is retried by the next run",
			"kind", pass.Kind, "credential_id", row.ID.String(), "error", err)
	default:
		pass.Resealed++
	}
}

// report writes one line per pass, and escalates the two states that matter.
//
// A job whose output nobody can see is a job nobody notices has stopped — and
// this one is worse than most, because its output is the input to an irreversible
// operator decision. The counts are per category for the reason the categories
// exist: a total of "200 processed" is entirely compatible with 200 secrets that
// could not be opened.
func (k *KeyReseal) report(pass ResealPass) {
	attrs := []any{
		"kind", pass.Kind, "key_version", pass.Version,
		"scanned", pass.Scanned, "resealed", pass.Resealed, "skipped", pass.Skipped,
		"unopenable", pass.Unopenable, "failed", pass.Failed,
		"remaining", pass.Remaining, "more", pass.More,
	}
	switch {
	case pass.Unopenable > 0:
		k.log.Error("credential re-sealing pass complete WITH UNOPENABLE ROWS; the old key "+
			"MUST NOT be destroyed", attrs...)
	case pass.Scanned == 0 && pass.Remaining > 0:
		// The empty-page trap, made visible. Nothing after the cursor and rows
		// still outstanding means everything left is behind the cursor because a
		// previous pass could not fix it — the exact state that looks finished.
		k.log.Warn("credential re-sealing found nothing after its cursor while rows are "+
			"still at an old key version; the rotation is STALLED, not complete", attrs...)
	default:
		k.log.Info("credential re-sealing pass complete", attrs...)
	}
}
