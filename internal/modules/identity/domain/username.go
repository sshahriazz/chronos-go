package domain

import (
	"strings"
	"unicode/utf8"

	"github.com/chronos/chronos-go/internal/platform/errs"
)

// Username normalization and screening, applied identically everywhere a handle
// is compared, claimed or checked for availability.
//
// A username is the one piece of user-supplied text this system deliberately
// PUBLISHES (ADR-051). That single fact decides every rule below, and it decides
// them differently from the way the same rules are decided for an address:
//
//   - An address is secret, so its normalization exists to stop one person
//     holding two accounts. A handle is public, so its normalization exists to
//     stop two people holding one identity — @alice and @Alice rendered side by
//     side in a mention list are an impersonation surface, not a duplicate.
//   - An address may be internationalized, because mail is. A handle may not,
//     because a handle is read by strangers who have no way to tell a Cyrillic
//     "а" from a Latin "a" and no reason to suspect there is anything to tell.
const (
	// MinUsernameBytes is the shortest handle. Three rather than one because a
	// one- and two-character space is small enough to exhaust in an afternoon,
	// and because every short handle a person could plausibly want is also a
	// handle a squatter wants.
	MinUsernameBytes = 3

	// MaxUsernameBytes is the longest. Thirty is generous for a mention and short
	// enough that a handle fits on one line beside a display name.
	//
	// It is also a HARD bound on the reservation stream's name, which is
	// "reservation_username-" plus the handle. A stream name is permanent, so an
	// unbounded one is an unbounded permanent artefact.
	MaxUsernameBytes = 30
)

// NormalizeUsername produces the canonical form used for claiming, comparison
// and stream naming.
//
// # The standard this follows, and where it deliberately narrows it
//
// RFC 8265 (PRECIS) is the governing specification for usernames, and it is
// already the one this module applies to passwords — password.go uses its
// OpaqueString profile (§4). A handle takes the OTHER profile from the same
// framework, UsernameCaseMapped (§3.3), and the pairing is the point of PRECIS:
// a password must NOT be case-folded or width-folded because folding destroys
// entropy, while an identifier MUST be, because two identifiers that differ only
// in case are two things one reader cannot tell apart.
//
// UsernameCaseMapped's order of operations is fixed and is followed here:
// width-map, then NFC, then case-fold, then validate. Order matters — folding
// before normalising lets `İ` (U+0130) decompose into `i` plus a combining dot,
// turning input the character set refuses into input it accepts. That is why the
// fold below is ASCII-only rather than strings.ToLower, and there is a test for
// exactly that input.
//
// This function then NARROWS the profile: UsernameCaseMapped permits RFC 8264's
// IdentifierClass, which is most of Unicode's letters and digits. The narrowing
// to ASCII is deliberate and is argued under "Confusables" below. It is recorded
// as a restriction OF the profile rather than as a bare character set, because
// that is what makes it reviewable — a reader can see which rule is the standard
// and which is ours, and PRECIS itself declines to solve confusables (RFC 8264
// §12.5 defers to UTS #39), so the narrowing is doing work the profile does not.
//
// Display names are a third profile again — RFC 8266's Nickname — and are not
// this function's business.
//
// The rules, and the reasoning for each:
//
//   - The character set is ASCII [a-z0-9_] and NOTHING else. It is validated
//     rather than mapped: input outside the set is refused, never folded into it.
//   - Case is FOLDED to lower. @Alice and @alice must be one handle, because two
//     accounts whose handles differ only in case are two accounts one reader
//     cannot tell apart. Only the folded form is stored; there is deliberately no
//     separate display casing, because a display form that differs from the
//     canonical one recreates the confusability problem inside a single account.
//   - A HYPHEN is not in the set, and that is a technical constraint rather than
//     a preference: the handle names a KurrentDB stream key, and
//     eventsourcing.NewStreamID refuses a dash in a key because KurrentDB derives
//     a category from everything before the first one. A handle containing a dash
//     could not be claimed at all, and the refusal would surface as an internal
//     error at append time rather than as a validation message.
//   - It must START with a letter. A handle beginning with a digit or an
//     underscore is indistinguishable at a glance from an identifier the system
//     generated, and a leading digit makes "@1234" ambiguous with any numeric id
//     a URL might carry.
//   - Underscores may not lead, trail or repeat. They carry no meaning, and each
//     permitted position multiplies the family of near-duplicates around an
//     existing handle at zero cost to whoever wants to impersonate it.
//
// # Confusables: what this does, and what it deliberately does not
//
// Restricting the set to ASCII eliminates the entire CROSS-SCRIPT homoglyph
// class outright — there is no Cyrillic "а", no Greek "ο", no fullwidth "ａ",
// because there is no non-ASCII input at all. That is the class that matters,
// because it produces handles that are byte-different and pixel-identical, and
// no amount of careful rendering distinguishes them.
//
// What remains is the WITHIN-ASCII class: 0/o, 1/l, rn/m, and the like. This
// function deliberately does NOT fold those, and the reason is that folding is
// worse than the problem:
//
//   - Folding 0 to o makes @bob and @b0b one handle, so the first registrant
//     silently denies a whole family of handles to everyone else, and the person
//     refused cannot see why.
//   - The mapping is not invertible, so the log cannot explain a refusal after
//     the fact: "that handle is taken" would be true of a handle that appears
//     nowhere.
//   - It is unbounded. rn/m, vv/w, cl/d and 1/l/I compose, so any serious
//     skeleton algorithm collapses a large fraction of the handle space, and the
//     fraction is not one anybody can enumerate in a code review.
//
// The residual risk is real and is answered at the RENDERING layer instead —
// where the reader is, which is the only place that has the context to answer it
// — by showing handles in a font that distinguishes 0 from o and by never
// presenting a handle as proof of who somebody is. That is stated here rather
// than left implicit so nobody later "fixes" this function into a skeleton
// matcher.
//
// # Reserved names are refused here, not in a projection
//
// Screening runs on the NORMALIZED form, so "Admin", "ADMIN" and "admin" are one
// refusal rather than three separate handles. See reservedUsernames.
func NormalizeUsername(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	switch {
	case trimmed == "":
		return "", errs.ValidationFailedf("a username is required")
	case !utf8.ValidString(trimmed):
		return "", errs.ValidationFailedf("a username must be valid UTF-8")
	case len(trimmed) < MinUsernameBytes:
		return "", errs.ValidationFailedf(
			"a username must be at least %d characters", MinUsernameBytes)
	case len(trimmed) > MaxUsernameBytes:
		return "", errs.ValidationFailedf(
			"a username may not exceed %d characters", MaxUsernameBytes)
	}

	// Lowercased with the ASCII rule and not strings.ToLower, because ToLower is
	// Unicode-aware and would map 'İ' to "i̇" — two code points, one of them a
	// combining mark — turning an input this function is about to refuse into one
	// it would accept. The set is ASCII, so the fold must be ASCII too.
	folded := asciiLower(trimmed)

	for i := range len(folded) {
		c := folded[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '_':
			switch {
			case i == 0 || i == len(folded)-1:
				return "", errs.ValidationFailedf(
					"a username may not begin or end with an underscore")
			case folded[i-1] == '_':
				return "", errs.ValidationFailedf(
					"a username may not contain two underscores in a row")
			}
		default:
			// One message for every rejected byte, and it names the whole rule
			// rather than the offending character. Naming the character would echo
			// caller-supplied bytes into an error string, and the rule is short
			// enough to state in full.
			return "", errs.ValidationFailedf(
				"a username may contain only the letters a-z, the digits 0-9 and underscores")
		}
	}
	if folded[0] < 'a' || folded[0] > 'z' {
		return "", errs.ValidationFailedf("a username must begin with a letter")
	}

	if IsReservedUsername(folded) {
		// Deliberately says WHY. A reserved name is a property of the system and
		// not of any account, so naming it discloses nothing about anybody — and
		// "that name is reserved" is the only message that tells the person to pick
		// a different KIND of name rather than to try again with a suffix.
		return "", errs.ValidationFailedf("that username is reserved")
	}
	return folded, nil
}

// asciiLower folds A-Z and touches nothing else.
//
// See NormalizeUsername for why this is not strings.ToLower: a Unicode fold can
// turn input the character-set rule would refuse into input it would accept, and
// a normalizer that admits by folding is a normalizer whose stated character set
// is not the one it enforces.
func asciiLower(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

// IsReservedUsername reports whether a NORMALIZED handle is one nobody may hold.
//
// The caller must have normalized first. Screening a raw string would let
// "Admin" through, and a case-varied impersonation of the operator is the exact
// thing this list exists to stop.
//
// Two families, and both need stating because they are refused for unrelated
// reasons:
//
//  1. ROLE IMPERSONATION — admin, support, billing, security, noreply. A handle
//     that reads as the operator is a phishing primitive that needs no technical
//     compromise at all: "@support asked me to confirm your password" is a
//     complete attack, and the only defence is that @support cannot exist.
//
//  2. ROUTE COLLISION — login, settings, api, new, about. A profile lives at a
//     path built from the handle, so a handle equal to a sibling route makes the
//     route ambiguous forever. It cannot be fixed later by changing the routing,
//     because by then somebody holds the handle and taking it away is an erasure
//     of an identity other people have linked to.
//
// The list is deliberately generous and deliberately static. Generous because a
// name added later cannot be reclaimed from whoever already holds it — the cost
// of reserving one name too many is a person picking a different handle, and the
// cost of reserving one too few is permanent. Static because a runtime-editable
// list would make "is this handle claimable" a question whose answer changes
// under a claim that has already been checked.
func IsReservedUsername(normalized string) bool {
	_, taken := reservedUsernames[normalized]
	return taken
}

// reservedUsernames is the screening list. See IsReservedUsername.
//
// Every entry is already in normalized form; a name here that would not survive
// NormalizeUsername is dead weight, and TestEveryReservedNameIsWellFormed says
// so.
var reservedUsernames = func() map[string]struct{} {
	names := []string{
		// Role impersonation.
		"abuse", "account", "accounts", "admin", "administrator", "billing",
		"chronos", "compliance", "founder", "help", "hostmaster", "legal",
		"mailer_daemon", "moderator", "noreply", "no_reply", "official",
		"operator", "owner", "postmaster", "privacy", "root", "security",
		"staff", "support", "sysadmin", "system", "team", "webmaster",

		// Route collision. Everything a profile path could sit beside.
		"about", "api", "assets", "auth", "callback", "contact", "docs", "edit",
		"explore", "favicon", "health", "home", "index", "invite", "invites",
		"login", "logout", "me", "metrics", "new", "oauth", "password", "pricing",
		"public", "register", "reset", "search", "session", "sessions",
		"settings", "signin", "signout", "signup", "sso", "static", "status",
		"terms", "user", "users", "verify", "webhook", "webhooks", "www",

		// Names that read as an absence. A handle rendering as "null" or
		// "undefined" in one client's template is indistinguishable from that
		// client having lost the value, which makes every such bug unreportable.
		"none", "null", "undefined", "unknown",
	}
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[n] = struct{}{}
	}
	return set
}()
