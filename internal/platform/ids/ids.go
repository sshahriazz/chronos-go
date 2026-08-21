// Package ids provides typed, prefixed identifiers (ADR-030).
//
// An identifier is a ULID rendered with a type prefix — org_01H8XG5N2QK7VB3C9WPYZR4TFM.
// Two properties matter:
//
//   - The Go types are distinct. OrgID and WorkspaceID cannot be confused by the
//     compiler, so passing one where the other is expected does not compile.
//   - The wire form is self-describing. Parsing validates the prefix, so a
//     wrong-type identifier is an InvalidArgument at the boundary rather than a
//     mysterious NotFound three layers in.
//
// The prefix separator is '_' deliberately: KurrentDB derives a stream's
// category from everything before the first '-', so a '-' here would corrupt
// stream naming (EVENT-SOURCING §2). ULIDs use Crockford base32, which contains
// no '-' either.
package ids

import (
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

// Kind is the phantom type that carries a prefix. Implementations are empty
// structs, so the prefix is reachable from the zero value without an instance.
type Kind interface{ Prefix() string }

// The registry. Every prefix is permanent: it is part of the public API
// (ADR-030), so changing one is a breaking change for every stored reference.
type (
	Org        struct{}
	Workspace  struct{}
	User       struct{}
	Team       struct{}
	Session    struct{}
	Credential struct{}

	Invitation   struct{}
	APIKey       struct{}
	Subscription struct{}
	Plan         struct{}
	PlanVersion  struct{}
	Notification struct{}
	Event        struct{}
	Subject      struct{}

	// PushSubscription is one browser profile on one device, in one
	// organization. Not one per person: a person commonly has several, and one
	// browser produces a distinct subscription in every organization they
	// belong to (ADR-043).
	PushSubscription struct{}
)

func (Org) Prefix() string       { return "org" }
func (Workspace) Prefix() string { return "ws" }
func (User) Prefix() string      { return "usr" }
func (Team) Prefix() string      { return "team" }
func (Session) Prefix() string   { return "sess" }

// Credential is one authentication method belonging to a user — a password, a
// TOTP secret, a passkey. One kind rather than three because the invariant that
// matters ("at least one usable method") spans all of them, and a per-method id
// type would let a caller pass a passkey id where a password id was expected.
func (Credential) Prefix() string { return "cred" }

func (Invitation) Prefix() string   { return "inv" }
func (APIKey) Prefix() string       { return "key" }
func (Subscription) Prefix() string { return "sub" } // matches Stripe's convention
func (Plan) Prefix() string         { return "plan" }
func (PlanVersion) Prefix() string  { return "pv" }
func (Notification) Prefix() string { return "notif" }
func (Event) Prefix() string        { return "evt" }
func (Subject) Prefix() string      { return "subj" } // pseudonym; appears in every event (ADR-002)

// PushSubscription's id is DERIVED from the organization and the endpoint
// rather than minted at random, so the same browser re-registering in the same
// organization resolves to the same subscription and a second organization
// resolves to a different one. It is therefore not time-ordered, which nothing
// sorts by, and it leaks no creation time — the one thing ADR-030 warns a ULID
// does.
func (PushSubscription) Prefix() string { return "push" }

// Registry reports every registered kind by name. Used by the conformance test
// that asserts prefixes are unique — a duplicate would make Parse ambiguous.
func Registry() map[string]string {
	return map[string]string{
		"Org": Org{}.Prefix(), "Workspace": Workspace{}.Prefix(),
		"User": User{}.Prefix(), "Team": Team{}.Prefix(),
		"Session": Session{}.Prefix(), "Credential": Credential{}.Prefix(),
		"Invitation": Invitation{}.Prefix(),
		"APIKey":     APIKey{}.Prefix(), "Subscription": Subscription{}.Prefix(),
		"Plan": Plan{}.Prefix(), "PlanVersion": PlanVersion{}.Prefix(),
		"Notification": Notification{}.Prefix(), "Event": Event{}.Prefix(),
		"Subject":          Subject{}.Prefix(),
		"PushSubscription": PushSubscription{}.Prefix(),
	}
}

// The WIRE GRAMMAR of a rendered identifier, stated once.
//
// # Why this lives here and not in each .proto
//
// Every request field naming an identifier carries a protovalidate `pattern`, and
// that pattern is published in the OpenAPI document and enforced by the
// validation interceptor BEFORE Parse ever runs. So there are two implementations
// of "what an identifier looks like": this file, and a regular expression written
// by hand in a .proto. When they disagree, the interceptor wins, and it wins by
// refusing values Parse would have accepted — a rule stricter than the handler,
// which is the failure CONVENTIONS §7.2 exists to prevent.
//
// They DID disagree, in both directions, and neither was visible:
//
//   - The hand-written patterns were UPPERCASE-ONLY, and `ulid.ParseStrict`
//     accepts lowercase. Every lowercase identifier — a value the parser took
//     without complaint — was refused at the boundary. That one was resolved by
//     making PARSE the strict half: an identifier renders in one case, so it is
//     read in one case, and the aliasing Parse explains at length is gone.
//   - The hand-written patterns allowed any Crockford character FIRST, and
//     ParseStrict does not: the leading character carries the top 3 bits of a
//     48-bit millisecond timestamp, so anything above '7' overflows and is
//     rejected. The published grammar described identifiers that cannot exist.
//
// PatternFor is now the only place the grammar is written, TestThePatternAgrees-
// WithParse asserts the two accept exactly the same strings, and
// internal/tools/checkopenapi fails the build if a published pattern is not the
// one this function returns. A .proto that hand-rolls its own gets a diff.
const (
	// crockford is Crockford base32: the digits, and the letters with I, L, O and
	// U removed because they are the ones misread off a screen.
	//
	// UPPER CASE ONLY. The encoding permits either case and Parse deliberately
	// does not — see the comment there for what an identifier that can be spelled
	// two ways does to an OpenFGA tuple and a stream name.
	crockford = "0-9A-HJKMNP-TV-Z"

	// leading is the first character of a ULID's 26. It encodes the top 3 bits of
	// the timestamp, so only 0-7 can appear; 8 and above is an overflow that
	// ulid.ParseStrict refuses.
	leading = "0-7"

	// bodyLen is the rendered length of a ULID.
	bodyLen = 26
)

// PatternFor returns the anchored regular expression a rendered identifier of
// this prefix matches — the value to paste into a `(buf.validate.field).string`
// rule.
//
// Anchored, because an unanchored pattern matches a substring, and an identifier
// that merely CONTAINS a valid one is not a valid one.
func PatternFor(prefix string) string {
	return "^" + prefix + "_[" + leading + "][" + crockford + "]{" + strconv.Itoa(bodyLen-1) + "}$"
}

// OptionalPatternFor is PatternFor with the empty string additionally admitted —
// the form for a field that may legitimately be absent, where protobuf-JSON
// renders "unset" as "".
//
// Spelled as an alternation rather than by dropping `required`, because the two
// say different things: `^$|^…$` says "empty or well-formed", and a missing rule
// says "anything".
func OptionalPatternFor(prefix string) string {
	return "^$|" + PatternFor(prefix)
}

// Pattern is PatternFor for a Kind known at compile time.
func Pattern[K Kind]() string { return PatternFor(prefixOf[K]()) }

// RenderedLen is the exact length of a rendered identifier — the value to use as
// `max_len`.
//
// Exact rather than approximate: every identifier of one kind is the same length,
// so a `max_len` larger than this admits a string no identifier can be.
func RenderedLen(prefix string) int { return len(prefix) + 1 + bodyLen }

// ID is a ULID tagged with its Kind at compile time.
type ID[K Kind] struct{ v ulid.ULID }

// Convenient aliases. These are aliases rather than defined types so that
// ID[Org] and OrgID are interchangeable, while OrgID and WorkspaceID remain
// distinct types.
type (
	OrgID          = ID[Org]
	WorkspaceID    = ID[Workspace]
	UserID         = ID[User]
	TeamID         = ID[Team]
	SessionID      = ID[Session]
	CredentialID   = ID[Credential]
	InvitationID   = ID[Invitation]
	APIKeyID       = ID[APIKey]
	SubscriptionID = ID[Subscription]
	PlanID         = ID[Plan]
	PlanVersionID  = ID[PlanVersion]
	NotificationID = ID[Notification]
	EventID        = ID[Event]
	SubjectID      = ID[Subject]

	// PushSubscriptionID is deliberately not abbreviated to PushID: the thing it
	// names is a subscription held by a push service, not a push that was sent.
	PushSubscriptionID = ID[PushSubscription]
)

var (
	ErrEmpty         = errors.New("ids: empty identifier")
	ErrMalformed     = errors.New("ids: malformed identifier")
	ErrWrongTypeCode = errors.New("ids: identifier is of the wrong type")
)

func prefixOf[K Kind]() string {
	var k K
	return k.Prefix()
}

// Entropy returns the production entropy source: crypto/rand, which never
// returns a short read. Use this rather than hand-rolling a reader — New panics
// on a failing source, and a bounded reader is the easy way to cause that.
func Entropy() io.Reader { return cryptorand.Reader }

// New mints an identifier. Clock and entropy are injected so tests are
// deterministic (CONVENTIONS §10) — nothing here reads the wall clock.
//
// Panics if entropy fails. That is deliberate: with crypto/rand it cannot
// happen, and an identifier generator that returns an error infects every
// call site with handling for a condition that never occurs.
func New[K Kind](at time.Time, entropy io.Reader) ID[K] {
	return ID[K]{v: ulid.MustNew(ulid.Timestamp(at.UTC()), entropy)}
}

// FromUUID builds an identifier from 16 deterministic bytes.
//
// Used for derived identifiers that must be reproducible — event ids computed
// from an idempotency key (EVENT-SOURCING §3). Such an id carries no meaningful
// timestamp, so Time() on it is not significant.
func FromUUID[K Kind](u [16]byte) ID[K] {
	return ID[K]{v: ulid.ULID(u)}
}

// Parse validates the prefix and the ULID body, and requires the CANONICAL
// rendering.
//
// # Why lowercase is refused
//
// Crockford base32 specifies case-insensitive DECODING, and `ulid.ParseStrict`
// implements that faithfully: it accepts `sess_01arz…` and `sess_01ARZ…` as the
// same 16 bytes. That is the right rule for a code a human reads off paper. It is
// the wrong rule for an identifier on a wire, because it makes two distinct
// strings name one entity, and this system compares identifier STRINGS in places
// that never parse them:
//
//   - an OpenFGA tuple is `user:usr_…` matched textually, so a tuple written in
//     one case and checked in the other does not match. It fails closed, so it is
//     not an escalation — it is an authorization decision that is silently wrong
//     in the safe direction, which is the hardest kind to find;
//   - a Valkey cache key, a Centrifugo channel and a KurrentDB stream name all
//     embed the rendered form, so an aliased identifier is two cache entries, two
//     channels and — worst — two streams for one aggregate.
//
// Nothing in this system ever RENDERS lowercase: String, AppendTo and MarshalText
// all go through ulid's uppercase encoder. So refusing it costs no round trip that
// works today, and it removes the aliasing entirely rather than asking every
// downstream user of the string to normalize first. A caller holding a lowercase
// identifier — a person typing into a support tool — uppercases it at that
// boundary, which is where the ambiguity belongs.
//
// PatternFor publishes exactly this rule, and TestThePatternAgreesWithParse
// asserts the two agree, so the validation interceptor refuses precisely what
// this function does.
func Parse[K Kind](s string) (ID[K], error) {
	var zero ID[K]
	if s == "" {
		return zero, ErrEmpty
	}
	want := prefixOf[K]()
	body, ok := strings.CutPrefix(s, want+"_")
	if !ok {
		return zero, fmt.Errorf("%w: expected prefix %q in %q", ErrWrongTypeCode, want, s)
	}
	// Checked before ParseStrict, which would accept it: a byte scan rather than
	// a ToUpper comparison, so a rejected identifier costs no allocation.
	for i := range len(body) {
		if body[i] >= 'a' && body[i] <= 'z' {
			return zero, fmt.Errorf(
				"%w: %q is not canonical — identifiers render in upper case", ErrMalformed, s)
		}
	}
	u, err := ulid.ParseStrict(body)
	if err != nil {
		return zero, fmt.Errorf("%w: %q", ErrMalformed, s)
	}
	return ID[K]{v: u}, nil
}

// MustParse is for tests and constants only.
func MustParse[K Kind](s string) ID[K] {
	id, err := Parse[K](s)
	if err != nil {
		panic(err)
	}
	return id
}

func (id ID[K]) IsZero() bool { return id.v == ulid.ULID{} }

// Bytes exposes the raw 16 bytes.
//
// For adapters that must hand the identifier to a driver in its own type — a
// KurrentDB event id, for instance. Domain code has no reason to call this.
func (id ID[K]) Bytes() [16]byte { return id.v }

// maxLen bounds the rendered form: the longest prefix plus '_' plus a 26-char
// ULID. Sized as a constant so AppendTo can use a stack array.
const maxLen = 8 + 1 + 26

// AppendTo appends the rendered identifier to dst and returns the extended
// slice, allocating nothing when dst has capacity.
//
// This is the zero-allocation path. Use it when building a response buffer or a
// stream name; String allocates because it must return a string.
func (id ID[K]) AppendTo(dst []byte) []byte {
	if id.IsZero() {
		return dst
	}
	dst = append(dst, prefixOf[K]()...)
	dst = append(dst, '_')
	// Grow once, then let ULID encode straight into the tail. MarshalTextTo
	// requires an exactly-sized destination, hence the reslice.
	dst = slices.Grow(dst, ulid.EncodedSize)
	n := len(dst)
	dst = dst[:n+ulid.EncodedSize]
	_ = id.v.MarshalTextTo(dst[n:])
	return dst
}

// String renders the prefixed form. The zero value renders empty rather than
// "org_00000000000000000000000000", so a missing id is visibly missing.
//
// Exactly one allocation — the returned string. Callers on a hot path that are
// already building a buffer should prefer AppendTo, which allocates nothing.
func (id ID[K]) String() string {
	if id.IsZero() {
		return ""
	}
	var buf [maxLen]byte
	return string(id.AppendTo(buf[:0]))
}

// Time is the embedded creation timestamp, always UTC (ADR-008).
func (id ID[K]) Time() time.Time {
	return ulid.Time(id.v.Time()).UTC()
}

func (id ID[K]) MarshalText() ([]byte, error) { return id.AppendTo(nil), nil }

// AppendText implements encoding.TextAppender (Go 1.24+), letting encoders
// render an identifier straight into their own buffer.
func (id ID[K]) AppendText(b []byte) ([]byte, error) { return id.AppendTo(b), nil }

func (id *ID[K]) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*id = ID[K]{}
		return nil
	}
	parsed, err := Parse[K](string(b))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}
