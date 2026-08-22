package argon2id

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/crypto"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"golang.org/x/crypto/argon2"
)

// Params are the Argon2id cost parameters.
//
// Stored PER VERIFIER rather than read from configuration at verify time. A
// global setting cannot verify a password hashed under the previous one, so
// raising the cost would invalidate every existing password — and the pressure
// to avoid that is exactly why costs never get raised.
type Params struct {
	// Memory in KiB. The dominant cost, and the one that actually resists GPUs:
	// memory-hardness is Argon2's entire reason for existing, so trading memory
	// down for iterations up defeats the algorithm choice.
	Memory uint32

	// Time is the number of passes.
	Time uint32

	// Parallelism is the number of lanes.
	Parallelism uint8

	// SaltLen and KeyLen in bytes.
	SaltLen uint32
	KeyLen  uint32
}

// DefaultParams: 32 MiB, 3 passes, 1 lane. Measured, not copied.
//
// On an 11-core arm64 development machine:
//
//	m=16 MiB t=2   17.5 ms
//	m=24 MiB t=2   26.4 ms
//	m=32 MiB t=2   34.3 ms
//	m=32 MiB t=3   51.1 ms   <- chosen
//	m=32 MiB t=4   67.7 ms
//	m=40 MiB t=3   65.4 ms
//	m=48 MiB t=2   54.3 ms
//	m=64 MiB t=2   75.9 ms
//
// Cost is close to linear in memory × passes, so there is no free point on the
// curve — an earlier reading that suggested 19 MiB and 32 MiB cost the same was
// warmup contamination in the first measurement, and re-running with the order
// changed removed it. Worth stating because "raise the memory, it is free" is
// exactly the conclusion a single unrepeated benchmark invites.
//
// 51 ms sits inside the usual 50–250 ms budget for an operation that happens
// once per login. Memory is capped at 32 MiB for an operational reason rather
// than a cryptographic one: every concurrent hash holds its full working set, so
// unbounded concurrency turns password verification into a memory amplification
// vector — a few hundred simultaneous attempts, which is not a large attack,
// exhausts the process.
//
// Two controls, and both are needed. WithConcurrencyLimit bounds the supply
// side, so peak memory is limit × Memory no matter what arrives. The attempt
// ceiling bounds the demand side, so reaching the limit is expensive for an
// attacker. Neither alone is enough: a bound without a ceiling sheds real logins
// during a stuffing run, and a ceiling without a bound still lets a distributed
// run spread across identifiers and arrive all at once.
//
// Retune on production hardware before launch. Raise Time before Memory, since
// Memory is the dimension with the operational ceiling above.
var DefaultParams = Params{
	Memory:      32 * 1024,
	Time:        3,
	Parallelism: 1,
	SaltLen:     16,
	KeyLen:      32,
}

// Hasher implements app.PasswordHasher.
type Hasher struct {
	params Params
	pepper *PepperKeys

	// slots bounds how many hashes run at once. See acquire.
	slots   chan struct{}
	limit   int
	maxWait time.Duration

	// rand is the salt source, injectable ONLY so a test can prove the failure
	// path is handled. Production always uses crypto/rand.
	rand io.Reader
}

var _ app.PasswordHasher = (*Hasher)(nil)

// Option configures a Hasher.
type Option func(*Hasher)

// WithConcurrencyLimit bounds simultaneous hashes and how long a caller waits
// for a slot.
//
// Sized from MEASUREMENT, not intuition. On an 11-core machine at m=32 MiB:
//
//	conc   throughput   p50      peak resident
//	  1       16/s      63ms       32 MiB
//	 11       92/s     110ms      352 MiB
//	 16       98/s     152ms      512 MiB
//	 32       91/s     294ms        1 GiB
//	128       81/s     903ms        4 GiB
//
// Throughput saturates at the core count and then DECLINES, because Argon2id
// with one lane is one core per hash — so concurrency beyond that buys no work
// at all and costs memory and latency linearly. 128 simultaneous logins is 4 GiB
// spent to do slightly less work than 16.
//
// That is what makes an unbounded hasher a memory amplification vector: a few
// hundred concurrent login attempts, which is not a large attack, exhausts the
// process. The bound converts that into a queue, and the queue into a bounded
// wait, and the wait into an honest refusal.
func WithConcurrencyLimit(n int, maxWait time.Duration) Option {
	// Records the intent; New validates it and allocates.
	//
	// Building the channel here would panic on a non-positive n — makechan
	// rejects a negative size — so a misconfiguration would crash the process at
	// wiring instead of returning the error New already has a branch for. An
	// option that can panic is an option that cannot be validated.
	return func(h *Hasher) {
		h.limit = n
		h.maxWait = maxWait
	}
}

// DefaultMaxWait is how long a caller queues before being shed.
//
// Short on purpose. A caller that waits seconds for a slot has already had a bad
// request; holding the connection open just converts a memory problem into a
// connection-count problem, and the client retries anyway.
const DefaultMaxWait = 2 * time.Second

// New builds a hasher.
//
// By default the concurrency limit is GOMAXPROCS — the measured saturation
// point. It is a limit rather than a tuning knob left unset: an unbounded
// default is the configuration nobody changes until an incident.
func New(pepper *PepperKeys, params Params, opts ...Option) (*Hasher, error) {
	if pepper == nil {
		return nil, fmt.Errorf("argon2id: a hasher needs pepper keys; without one every " +
			"stored verifier is a bare Argon2id digest and a database dump is crackable offline")
	}
	if err := params.validate(); err != nil {
		return nil, err
	}
	h := &Hasher{
		params:  params,
		pepper:  pepper,
		limit:   runtime.GOMAXPROCS(0),
		maxWait: DefaultMaxWait,
		rand:    rand.Reader,
	}
	for _, opt := range opts {
		opt(h)
	}
	if h.limit < 1 {
		return nil, fmt.Errorf("argon2id: concurrency limit is %d; it must be at least 1, "+
			"or every login blocks forever rather than being bounded", h.limit)
	}
	if h.maxWait <= 0 {
		return nil, fmt.Errorf("argon2id: the capacity wait is %v; a non-positive wait sheds "+
			"every caller that does not find a free slot instantly", h.maxWait)
	}
	h.slots = make(chan struct{}, h.limit)
	return h, nil
}

// acquire takes a hashing slot, or refuses.
//
// Three outcomes, and the third is the one that matters:
//
//   - a slot is free: proceed
//   - the caller's context ends: return its error, so a client that hung up
//     stops costing us 32 MiB
//   - the wait expires: RATE_LIMITED
//
// Shedding is deliberate. The alternative — queue everything — turns a memory
// bound into an unbounded queue, which is the same failure one indirection
// later. Refusing is also honest: the server IS at capacity, and RATE_LIMITED is
// what a client should back off from.
//
// It happens BEFORE any credential is examined, so it discloses nothing about
// whether the account exists or the password was right. A shed that depended on
// the answer would be an oracle.
func (h *Hasher) acquire(ctx context.Context) (release func(), err error) {
	// BEFORE the fast path, not only on the wait. A caller that has already hung
	// up gets ~50 ms of memory-hard work done on its behalf otherwise — and,
	// worse, occupies one of the slots this bound exists to ration, so a live
	// caller is shed to finish work nobody will read.
	//
	// It also makes "a cancelled caller is refused" true regardless of whether a
	// slot happens to be free, which is what a caller can actually reason about.
	// Checking only on the wait path made the answer depend on load: busy meant
	// refused, idle meant served.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	select {
	case h.slots <- struct{}{}:
		return func() { <-h.slots }, nil
	default:
	}

	timer := time.NewTimer(h.maxWait)
	defer timer.Stop()
	select {
	case h.slots <- struct{}{}:
		return func() { <-h.slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, errs.RateLimitedf("the server is at password-verification capacity; retry shortly")
	}
}

// InFlight reports how many hashes are running. For metrics and for the
// composition-root test that asserts the bound is actually wired.
func (h *Hasher) InFlight() int { return len(h.slots) }

// Limit reports the configured maximum.
func (h *Hasher) Limit() int { return cap(h.slots) }

// PepperVersion reports the key version Hash is currently sealing under.
//
// It exists because the version is written to its own column beside the
// verifier, so the rotation job can find rows sealed under an old key with
// `pepper_version < n` instead of parsing every verifier in the table. The
// hasher is the only component that knows the number, so it is the only one that
// can supply it.
//
// validVersion already refuses anything outside int32 at the moment a key enters
// the set, so the branch below is unreachable. It is written anyway, because a
// static checker cannot see that invariant and the alternative is a //nolint —
// which is a promise a reader has to take on trust rather than a check they can
// follow. The bound at the entry point is what makes this true; the check here is
// what makes it visible.
//
// The unreachable branch returns 0 rather than a truncated version, and 0 is a
// value the credential store refuses outright: a row written at 0 is invisible to
// the rotation job's `pepper_version < n` query, so it would be skipped silently
// and then locked out permanently when the old transit key was destroyed.
// Failing at the write is the only outcome that surfaces the problem while the
// password is still recoverable.
func (h *Hasher) PepperVersion() int32 {
	v := h.pepper.Current()
	if v < 1 || v > math.MaxInt32 {
		return 0
	}
	return int32(v)
}

func (p Params) validate() error {
	switch {
	case p.Memory < 8*1024:
		// Below ~8 MiB, Argon2id's memory-hardness stops meaning anything and it
		// degrades toward a fast hash — which is the thing it was chosen to
		// avoid. Refused rather than warned: a misconfigured cost is invisible
		// until a breach.
		return fmt.Errorf("argon2id: memory %d KiB is below the 8192 KiB floor", p.Memory)
	case p.Time < 1:
		return fmt.Errorf("argon2id: time cost must be at least 1")
	case p.Parallelism < 1:
		return fmt.Errorf("argon2id: parallelism must be at least 1")
	case p.SaltLen < 16:
		return fmt.Errorf("argon2id: salt length %d is below the 16-byte floor", p.SaltLen)
	case p.KeyLen < 32:
		return fmt.Errorf("argon2id: key length %d is below the 32-byte floor", p.KeyLen)
	}
	return nil
}

// Hash produces a verifier.
//
// The password is normalized here as well as at the API boundary. Duplicated
// deliberately: normalization applied at only one of set and verify is a lockout
// that ASCII test fixtures never reproduce, so both ends do it and the operation
// is idempotent (domain.NormalizePassword).
func (h *Hasher) Hash(
	ctx context.Context, password string, user ids.UserID, cred ids.CredentialID,
) (string, error) {
	normalized, err := domain.NormalizePassword(password)
	if err != nil {
		return "", err
	}
	if user.IsZero() || cred.IsZero() {
		// Without both ids the AAD binding is absent, and a verifier that is not
		// bound to its row can be copied onto another account. Refused rather
		// than defaulted to empty.
		return "", fmt.Errorf("argon2id: hashing needs both a user id and a credential id " +
			"to bind the verifier to its row")
	}

	version := h.pepper.Current()
	key, err := h.pepper.key(version)
	if err != nil {
		return "", err
	}

	salt := make([]byte, h.params.SaltLen)
	if _, err := io.ReadFull(h.rand, salt); err != nil {
		return "", fmt.Errorf("argon2id: generating salt: %w", err)
	}

	// Bounded here rather than around the whole method: everything above is
	// cheap, and holding a slot across it would idle a slot the machine could be
	// hashing with.
	release, err := h.acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()

	digest := argon2.IDKey([]byte(normalized), salt,
		h.params.Time, h.params.Memory, h.params.Parallelism, h.params.KeyLen)
	defer crypto.Zero(digest)

	sealed, err := crypto.Seal(key, digest, aad(user, cred))
	if err != nil {
		return "", fmt.Errorf("argon2id: sealing digest: %w", err)
	}
	return encode(h.params, version, salt, sealed), nil
}

// Verify checks a password against a stored verifier.
func (h *Hasher) Verify(
	ctx context.Context, password, verifier string, user ids.UserID, cred ids.CredentialID,
) (bool, error) {
	stored, err := decode(verifier)
	if err != nil {
		return false, err
	}
	normalized, err := domain.NormalizePassword(password)
	if err != nil {
		// A password that cannot even be normalized cannot match anything. This
		// is a mismatch, not an error: the alternative reports an internal
		// failure for a caller who typed a newline.
		return false, nil
	}

	key, err := h.pepper.key(stored.version)
	if err != nil {
		return false, fmt.Errorf("%w: %w", app.ErrVerifierUnreadable, err)
	}

	// Open, rather than re-seal and compare. GCM's nonce is random per call, so
	// sealing the same digest twice produces different bytes — comparing
	// ciphertexts would reject every correct password.
	want, err := crypto.Open(key, stored.sealed, aad(user, cred))
	if err != nil {
		// Reached when the row was copied from another account: the AAD does not
		// authenticate, so it cannot open. Deliberately reported as an ERROR
		// rather than a mismatch — a verifier that will not open under its own
		// row is tampering or an operational fault, and counting it as a wrong
		// password would hide both behind a normal-looking failed login.
		return false, fmt.Errorf("%w: %w", app.ErrVerifierUnreadable, err)
	}
	defer crypto.Zero(want)

	// The digest length comes from the opened plaintext, and decode has already
	// bounded it — so the conversion cannot wrap. Re-checked rather than assumed,
	// because a wrapped length here would be passed straight to argon2.IDKey as
	// an enormous output size.
	if len(want) > maxFieldBytes {
		return false, fmt.Errorf("%w: opened digest is %d bytes", app.ErrVerifierUnreadable, len(want))
	}
	// gosec cannot see the bound three lines above, so the conversion is
	// annotated rather than restructured — restructuring would mean widening
	// argon2.IDKey's own uint32 parameter, which is not ours to change.
	// Acquired AFTER the cheap rejections above — a malformed verifier or a
	// missing pepper key must not consume a hashing slot, or an attacker sheds
	// legitimate logins for free by replaying garbage.
	release, err := h.acquire(ctx)
	if err != nil {
		return false, err
	}
	defer release()

	//nolint:gosec // len(want) is bounded by maxFieldBytes immediately above
	got := argon2.IDKey([]byte(normalized), stored.salt,
		stored.params.Time, stored.params.Memory, stored.params.Parallelism,
		uint32(len(want)))
	defer crypto.Zero(got)

	// Constant time. A byte-wise == leaks how many leading bytes matched, which
	// over enough attempts recovers the digest — and the digest is what an
	// offline attack needs.
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// NeedsRehash reports whether a verifier is below current policy.
//
// Consulted after a successful verify, which is the only moment the plaintext
// exists. Any single dimension being behind is enough: a verifier at the right
// cost but an old pepper version still pins a row to a key operations are trying
// to retire.
func (h *Hasher) NeedsRehash(verifier string) bool {
	stored, err := decode(verifier)
	if err != nil {
		// Unreadable. Rehashing is the best available repair, and it is safe to
		// say yes: the caller only acts on this after the password verified,
		// which an unreadable verifier cannot do.
		return true
	}
	return stored.version != h.pepper.Current() ||
		stored.params.Memory < h.params.Memory ||
		stored.params.Time < h.params.Time ||
		stored.params.Parallelism < h.params.Parallelism ||
		stored.params.SaltLen < h.params.SaltLen ||
		stored.params.KeyLen < h.params.KeyLen
}

// aad is the additional authenticated data binding a verifier to its row.
//
// The separator is defensive rather than load-bearing today: both identifiers
// are prefixed ULIDs of fixed length (ADR-030), so plain concatenation is
// already unambiguous. It is here because that property is a fact about the id
// format, not about this function — a future variable-length identifier would
// silently reintroduce the ambiguity, and the failure would be a verifier that
// moves between two rows whose concatenations happen to coincide.
//
// A colon cannot appear in a prefixed ULID, so it cannot itself be forged into
// the boundary.
func aad(user ids.UserID, cred ids.CredentialID) []byte {
	b := make([]byte, 0, 64)
	b = user.AppendTo(b)
	b = append(b, ':')
	b = cred.AppendTo(b)
	return b
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

// The stored form, one text column:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$k=3$<sealed>
//
// PHC-shaped, with one deliberate difference: the final field is the SEALED
// digest, not the digest. Anything that reads this as a PHC string and compares
// the last field against a computed Argon2id output will simply never match,
// which is the correct way for that mistake to fail.
const (
	scheme     = "argon2id"
	argonVer   = 19 // argon2.Version, as the reference implementation numbers it
	fieldCount = 7

	// maxFieldBytes bounds the decoded salt and sealed digest.
	//
	// Generous — real values are 16 and 60 bytes — and load-bearing anyway: it is
	// what makes the int-to-uint32 conversions below provably safe. Without it a
	// hostile row could carry a length that wraps on conversion and reaches
	// argon2.IDKey as an enormous requested output size.
	maxFieldBytes = 1024
)

type stored struct {
	params  Params
	version int
	salt    []byte
	sealed  []byte
}

var b64 = base64.RawStdEncoding

func encode(p Params, pepperVersion int, salt, sealed []byte) string {
	var b strings.Builder
	b.WriteString("$" + scheme + "$v=")
	b.WriteString(strconv.Itoa(argonVer))
	b.WriteString("$m=")
	b.WriteString(strconv.FormatUint(uint64(p.Memory), 10))
	b.WriteString(",t=")
	b.WriteString(strconv.FormatUint(uint64(p.Time), 10))
	b.WriteString(",p=")
	b.WriteString(strconv.FormatUint(uint64(p.Parallelism), 10))
	b.WriteString("$")
	b.WriteString(b64.EncodeToString(salt))
	b.WriteString("$k=")
	b.WriteString(strconv.Itoa(pepperVersion))
	b.WriteString("$")
	b.WriteString(b64.EncodeToString(sealed))
	return b.String()
}

func decode(s string) (stored, error) {
	var out stored
	parts := strings.Split(s, "$")
	// A leading "$" produces an empty first field, so a well-formed value has
	// seven parts.
	if len(parts) != fieldCount || parts[0] != "" {
		return out, fmt.Errorf("%w: %d fields", app.ErrVerifierUnreadable, len(parts))
	}
	if parts[1] != scheme {
		return out, fmt.Errorf("%w: algorithm %q is not %q",
			app.ErrVerifierUnreadable, parts[1], scheme)
	}
	if parts[2] != "v="+strconv.Itoa(argonVer) {
		return out, fmt.Errorf("%w: argon2 version %q", app.ErrVerifierUnreadable, parts[2])
	}

	var memory, timeCost uint64
	var lanes uint64
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &lanes); err != nil {
		return out, fmt.Errorf("%w: cost parameters %q", app.ErrVerifierUnreadable, parts[3])
	}
	if memory > 1<<32-1 || timeCost > 1<<32-1 || lanes > 255 || memory == 0 || timeCost == 0 || lanes == 0 {
		return out, fmt.Errorf("%w: cost parameters out of range", app.ErrVerifierUnreadable)
	}

	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return out, fmt.Errorf("%w: salt is not base64", app.ErrVerifierUnreadable)
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[5], "k="))
	if err != nil || !strings.HasPrefix(parts[5], "k=") || version < 1 {
		return out, fmt.Errorf("%w: pepper key version %q", app.ErrVerifierUnreadable, parts[5])
	}
	sealed, err := b64.DecodeString(parts[6])
	if err != nil {
		return out, fmt.Errorf("%w: sealed digest is not base64", app.ErrVerifierUnreadable)
	}

	// The digest length is recovered from the sealed length rather than stored.
	//
	// crypto.Seal prefixes a 12-byte GCM nonce and appends a 16-byte tag, both
	// fixed, so the plaintext length is exact arithmetic. Leaving this at zero —
	// the tempting "it comes back from Open anyway" — makes NeedsRehash compare
	// 0 < KeyLen and report true for EVERY verifier, so every successful login
	// rehashes and the signal that a rehash is actually needed disappears.
	const gcmOverhead = 12 + 16
	if len(sealed) <= gcmOverhead || len(sealed) > maxFieldBytes {
		return out, fmt.Errorf("%w: sealed digest is %d bytes",
			app.ErrVerifierUnreadable, len(sealed))
	}
	if len(salt) > maxFieldBytes {
		return out, fmt.Errorf("%w: salt is %d bytes", app.ErrVerifierUnreadable, len(salt))
	}
	out.params = Params{
		Memory:      uint32(memory),
		Time:        uint32(timeCost),
		Parallelism: uint8(lanes),
		//nolint:gosec // both lengths are bounded by maxFieldBytes just above
		SaltLen: uint32(len(salt)),
		//nolint:gosec // ditto
		KeyLen: uint32(len(sealed) - gcmOverhead),
	}
	out.version = version
	out.salt = salt
	out.sealed = sealed
	return out, nil
}
