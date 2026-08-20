package temporal

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.temporal.io/sdk/activity"
	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// ResealCredentialKeysWorkflow carries credential secrets onto the current
// sealing key so that a key rotation can actually be completed.
//
// The name is PERSISTED in workflow history and in the schedule that starts it,
// so it is permanent in the same way SweepReservationsWorkflow and
// PurgeIdentityRetentionWorkflow are: renaming it leaves the schedule pointing at
// a workflow no worker answers to.
//
// The symptom of that gap is different from both of theirs, and worse. A missing
// reservation sweep eventually reaches a user who cannot register; a missing
// retention job reaches nobody until a table is enormous. A missing re-sealing
// job reaches nobody either — right up until an operator, seeing a count that
// never falls, either keeps a leaked key alive forever or destroys it anyway. The
// second of those permanently and irreversibly removes every password and every
// second factor still sealed under it.
const ResealCredentialKeysWorkflow = "chronos.identity.ResealCredentialKeys.v1"

// The two I/O steps. Both live in activities because workflow code must be
// deterministic — no clock, no randomness, no network — and reading a work list,
// opening ciphertext and writing it back are all I/O.
const (
	resealBatchActivity = "chronos.identity.ResealCredentialBatch.v1"
	resealKindsActivity = "chronos.identity.ResealableCredentialKinds.v1"
)

// ResealCredentialKeysInput parametrises one run.
//
// It carries no secret, no verifier, no ciphertext and no address. Workflow input
// is written to history, which is durable and replicated, so ADR-002 applies to
// it exactly as it does to the event log.
//
// It also carries no KEY VERSION and no list of kinds. Both are read from the
// running process, through the activity, on purpose: a schedule is server-side
// state and EnsureResealSchedule deliberately never updates an existing one, so
// anything baked into the schedule's arguments is frozen at the moment it was
// first created. A version pinned there would still name the key that was current
// last year, and a kind list pinned there would silently exclude any credential
// kind added afterwards — which is precisely the shape of the bug that made this
// job necessary, where TOTP rows were invisible to a query written when passwords
// were the only sealed value.
type ResealCredentialKeysInput struct {
	// Batch is the per-pass LIMIT on the work list. Bounded because each row
	// costs an AEAD open, an AEAD seal and a write, and an unbounded pass would
	// load every credential in the system into one activity.
	Batch int

	// MaxPasses bounds the passes PER KIND. The job loops while its batches keep
	// filling, so without a cap one execution's history would grow with the size
	// of the backlog.
	MaxPasses int
}

// ResealKindResult is what one run did for one credential kind.
//
// Per kind rather than one total, and that is not tidiness. The password pepper
// and the TOTP sealing key are separate key sets with unrelated version
// sequences, so "480 rows re-sealed" is entirely compatible with every TOTP
// secret still sitting on the old key — the exact state that once made this
// area's central query report a clean zero while every second factor depended on
// a key an operator had been told was safe to destroy.
type ResealKindResult struct {
	// Kind is the credential kind, as it appears in the column.
	Kind string

	// Version is the key version rows were moved TO.
	Version int32

	// Passes, Scanned, Resealed, Skipped and Failed are the run's counters.
	// Skipped covers rows that needed nothing: a compare-and-set lost to a
	// login-time rehash, a password change or a TOTP re-enrollment, all of which
	// wrote a value under the CURRENT key and are therefore successes for the
	// rotation rather than failures of this job.
	Passes   int
	Scanned  int
	Resealed int
	Skipped  int
	Failed   int

	// Unopenable is how many rows could not be opened under any loaded key.
	//
	// Reported apart from Failed because it is a categorically different event.
	// A failure is retried and costs a delay. An unopenable secret is an account
	// that LOSES its password or its second factor the moment the old key is
	// destroyed, unrecoverably, because the plaintext exists nowhere else. Any
	// non-zero value here means the rotation must stop until the key that sealed
	// those rows is loaded.
	Unopenable int

	// Remaining is the done check, taken after the last pass: rows of this kind
	// still below the current key version, anywhere in the table. ZERO, and only
	// zero, is what makes it safe to destroy the old key.
	Remaining int64

	// Counted reports that the last pass's done check actually ran. Without it,
	// a COUNT that failed would leave Remaining at zero and read as a completed
	// rotation — the answer that gets an in-use key destroyed.
	Counted bool

	// Truncated reports that this kind stopped at MaxPasses with its last batch
	// still full, so rows were left behind. It is part of the RESULT rather than
	// a log line for the reason SweepReservationsResult.Truncated is: a run that
	// quietly stopped at its limit reads as "everything is re-sealed".
	Truncated bool
}

// ResealCredentialKeysResult is what one run did, per kind.
//
// It is the run's OUTPUT rather than a log line. Workflow results are visible in
// the Temporal UI and in visibility queries long after logs have rotated, and
// "did the re-sealing job ever finish" is the question that decides whether an
// old transit key is destroyed — a decision nobody should have to answer from a
// grep of yesterday's logs.
type ResealCredentialKeysResult struct {
	// Kinds is one entry per credential kind, in the order they ran.
	Kinds []ResealKindResult

	// Resealed and Unopenable are the sums across kinds, for a quick read.
	Resealed   int
	Unopenable int

	// Truncated is true when ANY kind stopped at its pass limit.
	Truncated bool

	// Complete reports that EVERY kind has zero rows left below its current key
	// version — the one and only condition under which an old key may be
	// destroyed.
	//
	// It is derived from the per-kind COUNT, never from an empty page. An empty
	// page means "nothing after the cursor", which is also what a job produces
	// when everything left is behind its cursor because it could not be
	// re-sealed. Those two states are indistinguishable from the page alone and
	// opposite in consequence.
	Complete bool
}

// resealDefaults are the bounds a start that names neither gets.
//
// 200 x 20 = 4000 rows per kind per run. Sized against the schedule interval
// rather than against Postgres: at hourly, a deployment whose credential table is
// larger than this drains over a few hours, which is well inside the window an
// operator waits before destroying a key — and Truncated is how a backlog that is
// not draining becomes visible instead of silent.
const (
	defaultResealBatch     = 200
	defaultResealMaxPasses = 20
)

// withDefaults fills in what a start left unset.
//
// Deterministic and pure — it runs inside the workflow, where a value that
// differed between the original execution and a replay would corrupt history.
func (in ResealCredentialKeysInput) withDefaults() ResealCredentialKeysInput {
	if in.Batch <= 0 {
		in.Batch = defaultResealBatch
	}
	if in.MaxPasses <= 0 {
		in.MaxPasses = defaultResealMaxPasses
	}
	return in
}

// ResealCredentialKeys drains every kind's backlog in bounded passes.
//
// # The loop, and the cursor
//
// The work list is LIMITed and ordered by credential id, and each pass resumes
// strictly AFTER the last row the previous one looked at. The cursor is what
// makes the job resumable past a row it cannot fix: a credential that fails to
// re-seal keeps its old key version, so it matches the work list again — without
// a cursor it would come back at the head of every page and one unopenable secret
// would pin the whole rotation to the first two hundred rows forever, while every
// pass reported that it had scanned work.
//
// The cursor is a credential id. It crosses into workflow history, which is
// durable and replicated, and that is acceptable where a secret would not be: a
// credential id is a prefixed ULID (ADR-030), not personal data and not key
// material. Nothing else from the row travels.
//
// # Why one workflow for both kinds
//
// The password pepper and the TOTP sealing key differ in which key set opens a
// value and which primitive re-seals it, and in nothing else — same table, same
// version column, same work list, same compare-and-set, same done check. Two
// workflows would duplicate all of that, and the duplicate is where they would
// drift; this area's previous bug was exactly a divergence of that kind.
//
// They run as SEPARATE PASSES with their own cursors and their own counts, because
// their version sequences are unrelated: pepper v3 says nothing about totpseal v3.
//
// # No clock
//
// Unlike the sweep and the retention job, this workflow reads no clock at all.
// Nothing here is measured against a deadline: a row is due for re-sealing because
// of its key version, which is a fact about the row, not about the time.
func ResealCredentialKeys(
	ctx workflow.Context, in ResealCredentialKeysInput,
) (ResealCredentialKeysResult, error) {
	in = in.withDefaults()

	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		// One pass: a bounded batch of AEAD opens, seals and writes. Generous
		// against a slow database, short enough that a hung one is retried rather
		// than waited on for the whole run.
		StartToCloseTimeout: 5 * time.Minute,
		RetryPolicy: &sdktemporal.RetryPolicy{
			InitialInterval:    5 * time.Second,
			BackoffCoefficient: 2,
			MaximumInterval:    time.Minute,
			// Bounded by ScheduleToClose rather than by attempts: the next
			// scheduled run picks up whatever this one could not do, and it picks
			// it up from the beginning because a re-sealed row simply stops
			// matching the work list.
			MaximumAttempts: 0,
			// An input the activity refuses is refused identically forever.
			NonRetryableErrorTypes: []string{errTypePermanent},
		},
		ScheduleToCloseTimeout: 30 * time.Minute,
	})

	log := workflow.GetLogger(ctx)

	var kinds []string
	if err := workflow.ExecuteActivity(ctx, resealKindsActivity).Get(ctx, &kinds); err != nil {
		return ResealCredentialKeysResult{}, fmt.Errorf("reading the re-sealable credential "+
			"kinds: %w", err)
	}
	if len(kinds) == 0 {
		// The activity already refuses this, so reaching it means the refusal was
		// removed. Returned as a FAILURE rather than an empty success: a run that
		// re-sealed nothing because it was wired to nothing must never appear in
		// the UI as a completed rotation.
		return ResealCredentialKeysResult{}, errors.New("no credential kind is wired for " +
			"re-sealing, so this run would report a completed rotation over untouched rows")
	}

	// Complete starts true and is falsified by any kind with rows left. Written
	// this way round deliberately: the value that licenses destroying a key must
	// be the conjunction of every kind's done check, so a kind that is skipped or
	// added later cannot leave it true by omission — it has nothing to falsify it
	// only when there is genuinely nothing left.
	res := ResealCredentialKeysResult{
		Kinds:    make([]ResealKindResult, 0, len(kinds)),
		Complete: true,
	}
	for _, kind := range kinds {
		got, err := resealOneKind(ctx, kind, in)
		if err != nil {
			// Falsified before returning: a result carrying Complete: true beside
			// an error is the one combination that could be misread as "the
			// rotation finished", and it is the reading that destroys a key.
			res.Complete = false
			// Returned rather than swallowed. "The re-sealing job is broken" and
			// "there was nothing left to re-seal" must never look alike, because
			// one of them is the operator's signal to destroy a key.
			return res, fmt.Errorf("re-sealing %s credentials: %w", kind, err)
		}

		res.Kinds = append(res.Kinds, got)
		res.Resealed += got.Resealed
		res.Unopenable += got.Unopenable
		res.Truncated = res.Truncated || got.Truncated
		res.Complete = res.Complete && got.Counted && got.Remaining == 0

		switch {
		case got.Unopenable > 0:
			log.Error("CREDENTIALS COULD NOT BE OPENED UNDER ANY LOADED KEY. They were left "+
				"untouched, and destroying the old key removes those authentication methods "+
				"permanently. Load the key versions those rows name before continuing",
				"kind", got.Kind, "unopenable", got.Unopenable, "remaining", got.Remaining)
		case got.Truncated:
			log.Warn("credential re-sealing stopped at its pass limit with work remaining; "+
				"the old key is still in use and must not be destroyed",
				"kind", got.Kind, "passes", got.Passes, "remaining", got.Remaining)
		case got.Remaining > 0 && got.Resealed == 0 && got.Failed == 0:
			// Nothing moved, nothing failed, and rows are still outstanding. That
			// is the STALLED state: everything left is behind the cursor, so no
			// pass will ever reach it again, and every future run will look
			// exactly this quiet.
			log.Warn("credential re-sealing moved nothing while rows are still at an old key "+
				"version; the rotation is stalled rather than complete",
				"kind", got.Kind, "remaining", got.Remaining)
		default:
			log.Info("credential re-sealing complete for kind",
				"kind", got.Kind, "resealed", got.Resealed, "skipped", got.Skipped,
				"remaining", got.Remaining)
		}
	}
	return res, nil
}

// resealOneKind drains one credential kind, carrying the cursor between passes.
func resealOneKind(
	ctx workflow.Context, kind string, in ResealCredentialKeysInput,
) (ResealKindResult, error) {
	out := ResealKindResult{Kind: kind}

	cursor := ""
	for pass := 1; pass <= in.MaxPasses; pass++ {
		var got ResealBatch
		err := workflow.ExecuteActivity(ctx, resealBatchActivity, ResealBatchInput{
			Kind:  kind,
			After: cursor,
			Limit: in.Batch,
		}).Get(ctx, &got)
		if err != nil {
			return out, fmt.Errorf("pass %d: %w", pass, err)
		}

		out.Passes = pass
		out.Version = got.Version
		out.Scanned += got.Scanned
		out.Resealed += got.Resealed
		out.Skipped += got.Skipped
		out.Unopenable += got.Unopenable
		out.Failed += got.Failed
		// Overwritten rather than accumulated: it is the state AFTER this pass,
		// and only the last pass's value is the answer.
		out.Remaining, out.Counted = got.Remaining, got.Counted

		cursor = got.Cursor
		if !got.More {
			return out, nil
		}
		out.Truncated = pass == in.MaxPasses
	}
	return out, nil
}

// ResealBatchInput is the batch activity's argument.
//
// After is a credential id and nothing else — no verifier, no secret, no
// ciphertext. It is the only per-row value that crosses this boundary, and it
// crosses because resumption past an unfixable row depends on it.
type ResealBatchInput struct {
	Kind  string
	After string
	Limit int
}

// ResealBatch is one pass's counters, crossing the activity boundary.
//
// It mirrors the use case's result rather than sharing the type, which keeps this
// adapter free of the identity module — the same reason SweepPass and
// StatementResult are declared here.
type ResealBatch struct {
	Version    int32
	Scanned    int
	Resealed   int
	Skipped    int
	Unopenable int
	Failed     int

	// Cursor is where the next pass resumes: the last credential id looked at,
	// whatever the outcome for that row was.
	Cursor string

	// More reports that the page filled, so there is likely work after the
	// cursor. It is what makes the workflow loop instead of guessing.
	More bool

	// Remaining is the count of rows of this kind still below the current key
	// version, ANYWHERE — not merely after the cursor. It is the only value that
	// answers "may the old key be destroyed", and it is carried separately from
	// More for exactly that reason: More is about this page, Remaining is about
	// the table.
	Remaining int64

	// Counted reports that the done check actually ran. Remaining's zero value
	// and its "nothing left" value are the same number, and that number is what
	// an operator acts on.
	Counted bool
}

// CredentialResealer is the activity's dependency: the identity use case that
// knows how to open a stored value under an old key and re-seal it under the
// current one.
//
// Declared as an interface so this package neither depends on the identity module
// nor can be tempted into deciding anything for it — least of all which rows are
// safe to leave behind. It is also what keeps every key out of this package: the
// activity moves opaque strings and counters, and never sees a key or a plaintext.
type CredentialResealer interface {
	// Kinds is the set of credential kinds that are actually wired, sorted.
	Kinds() []string

	// ResealOnce re-seals at most limit rows of one kind, after a cursor.
	ResealOnce(ctx context.Context, kind, after string, limit int) (ResealBatch, error)
}

// ResealActivities holds the I/O half of the re-sealing job.
type ResealActivities struct{ resealer CredentialResealer }

// NewResealActivities builds the activity set.
func NewResealActivities(r CredentialResealer) (*ResealActivities, error) {
	if r == nil {
		return nil, errors.New("temporal: the credential re-sealing activity needs a " +
			"resealer; without one every run would report a completed rotation while every " +
			"password verifier and every TOTP secret stayed pinned to the key an operator " +
			"is waiting to destroy")
	}
	return &ResealActivities{resealer: r}, nil
}

// Kinds reports which credential kinds this deployment can re-seal.
//
// It is an activity rather than a constant in the workflow input so the answer
// comes from the RUNNING process. A schedule's arguments are frozen at creation —
// EnsureResealSchedule never updates an existing schedule, deliberately — so a
// kind list baked in there would silently exclude any kind added later, which is
// the precise shape of the bug this job exists to prevent.
func (a *ResealActivities) Kinds(context.Context) ([]string, error) {
	kinds := a.resealer.Kinds()
	if len(kinds) == 0 {
		return nil, sdktemporal.NewNonRetryableApplicationError(
			"no credential kind is wired for re-sealing, so a rotation could never complete",
			errTypePermanent, errors.New("no resealers"))
	}
	return kinds, nil
}

// Reseal performs one bounded pass.
//
// It returns an error only when the pass could not be ATTEMPTED — a bad input, an
// unreadable work list. Individual rows that fail are counted and reported inside
// the result, because one credential whose value cannot be opened must not stop
// every other account from being carried onto the new key, and because the row
// keeps its old version and is therefore visited again.
func (a *ResealActivities) Reseal(
	ctx context.Context, in ResealBatchInput,
) (ResealBatch, error) {
	if in.Kind == "" {
		return ResealBatch{}, sdktemporal.NewNonRetryableApplicationError(
			"a re-sealing pass with no credential kind selects no work list", errTypePermanent,
			errors.New("no kind supplied"))
	}
	if in.Limit <= 0 {
		return ResealBatch{}, sdktemporal.NewNonRetryableApplicationError(
			"a re-sealing limit of zero moves no rows and never will", errTypePermanent,
			fmt.Errorf("limit %d", in.Limit))
	}
	return a.resealer.ResealOnce(ctx, in.Kind, in.After, in.Limit)
}

// RegisterCredentialReseal adds the re-sealing job to a worker, returning the
// workflow names it now answers to.
//
// It returns the names rather than nothing so a composition-root test can assert
// the binary registered them WITHOUT starting a worker or reaching Temporal.
// Three adapters in this repository were once fully built, fully tested and
// constructed by no binary. Here the equivalent gap has no symptom at all until
// an operator reads a count that never falls and draws one of the two possible
// conclusions — keep a leaked key forever, or destroy a key that rows still need.
func (w *Worker) RegisterCredentialReseal(a *ResealActivities) ([]string, error) {
	if w == nil || w.w == nil {
		return nil, errors.New("temporal: cannot register credential re-sealing on a nil worker")
	}
	if a == nil {
		return nil, errors.New("temporal: refusing to register credential re-sealing with no " +
			"activity set; the schedule would start runs that fail on every task")
	}
	registerReseal(w.w, a)
	return []string{ResealCredentialKeysWorkflow}, nil
}

// registerReseal is the ONE place these names are bound to the code, so the
// worker and the test cannot register different things under the same names. It
// takes the same narrow registry the sweep and retention do, which is what lets
// the SDK's test environment go through production's registration path.
func registerReseal(r registry, a *ResealActivities) {
	r.RegisterWorkflowWithOptions(ResealCredentialKeys,
		workflow.RegisterOptions{Name: ResealCredentialKeysWorkflow})
	r.RegisterActivityWithOptions(a.Reseal,
		activity.RegisterOptions{Name: resealBatchActivity})
	r.RegisterActivityWithOptions(a.Kinds,
		activity.RegisterOptions{Name: resealKindsActivity})
}
