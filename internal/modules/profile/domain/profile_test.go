package domain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/profile/contract"
	"github.com/chronos/chronos-go/internal/modules/profile/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

const subject = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"

func at() time.Time { return time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC) }

func TestParseDisplayName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
		// why records what the rule protects, so a future reader deleting a case
		// has to argue with the reason rather than with the assertion.
		why string
	}{
		{
			name:  "kept as written",
			input: "Ada Lovelace",
			want:  "Ada Lovelace",
			why:   "a name is displayed verbatim; normalising it would rename people",
		},
		{
			name:  "surrounding whitespace is trimmed",
			input: "  Ada Lovelace\t",
			want:  "Ada Lovelace",
			why:   "leading space renders as a gap and sorts a person to the top of every list",
		},
		{
			name:  "non-latin scripts are names too",
			input: "山田太郎",
			want:  "山田太郎",
			why:   "an ASCII-only rule excludes most of the world from having a name",
		},
		{
			name:  "eighty runes is the ceiling and is allowed",
			input: strings.Repeat("é", 80),
			want:  strings.Repeat("é", 80),
			why: "the limit counts RUNES, so a two-byte script is not three times " +
				"stricter than ASCII",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := domain.ParseDisplayName(tt.input)
			if err != nil {
				t.Fatalf("ParseDisplayName(%q) = %v, want it accepted (%s)", tt.input, err, tt.why)
			}
			if got != tt.want {
				t.Fatalf("ParseDisplayName(%q) = %q, want %q (%s)", tt.input, got, tt.want, tt.why)
			}
		})
	}
}

func TestParseDisplayNameRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		why   string
	}{
		{
			name:  "empty",
			input: "",
			why:   "a blank name is a gap where an identity should be; removal is a different request",
		},
		{
			name:  "whitespace only",
			input: "   \t ",
			why:   "trims to empty, and would otherwise store a name that renders as nothing",
		},
		{
			name:  "right-to-left override",
			input: "Ada\u202EecilA",
			why: "a bidi override reorders the text AROUND it, so one name can impersonate " +
				"another's rendering, and it is invisible to every reviewer",
		},
		{
			name:  "zero-width joiner",
			input: "Ada\u200DLovelace",
			why:   "invisible by construction, so two distinct names render identically",
		},
		{
			name:  "newline",
			input: "Ada\nLovelace",
			why:   "a name is one line; a second one breaks every header it is rendered into",
		},
		{
			name:  "line separator",
			input: "Ada Lovelace",
			why:   "the Unicode line separator is a newline that unicode.IsControl does not catch",
		},
		{
			name:  "one rune over the ceiling",
			input: strings.Repeat("a", 81),
			why:   "the vault is the one store that cannot be rebuilt, so an unbounded row is permanent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := domain.ParseDisplayName(tt.input); err == nil {
				t.Fatalf("ParseDisplayName(%q) was accepted, want a refusal (%s)", tt.input, tt.why)
			} else if !errors.Is(err, domain.ErrDisplayNameRefused) {
				t.Fatalf("ParseDisplayName(%q) = %v, want it to wrap ErrDisplayNameRefused",
					tt.input, err)
			}
		})
	}
}

func TestParseLocale(t *testing.T) {
	t.Parallel()

	accepted := []string{"en", "en-GB", "de-AT", "zh-Hans", "zh-Hans-CN", "es-419", "nds"}
	for _, tag := range accepted {
		t.Run("accepts/"+tag, func(t *testing.T) {
			t.Parallel()
			got, err := domain.ParseLocale(tag)
			if err != nil {
				t.Fatalf("ParseLocale(%q) = %v, want it accepted", tag, err)
			}
			if got != tag {
				t.Fatalf("ParseLocale(%q) = %q; case is significant in BCP-47 and must not "+
					"be rewritten", tag, got)
			}
		})
	}

	refused := map[string]string{
		"":                "empty is not a locale; removal is a different request",
		"EN":              "the language subtag is lowercase in BCP-47; silently fixing it hides a client bug",
		"en-gb":           "the region subtag is uppercase; the same reasoning",
		"english":         "not a subtag shape anything renders from",
		"en-GB-oxendict":  "a variant subtag nothing here reads, so accepting it makes the field free text",
		"en-US-u-ca-greg": "an extension subtag, same reasoning",
		"e":               "one letter is not a language",
		"en-XYZ":          "neither a two-letter region nor a three-digit one",
	}
	for tag, why := range refused {
		t.Run("refuses/"+tag, func(t *testing.T) {
			t.Parallel()
			if _, err := domain.ParseLocale(tag); err == nil {
				t.Fatalf("ParseLocale(%q) was accepted, want a refusal (%s)", tag, why)
			} else if !errors.Is(err, domain.ErrLocaleRefused) {
				t.Fatalf("ParseLocale(%q) = %v, want it to wrap ErrLocaleRefused", tag, err)
			}
		})
	}
}

// TestParseTimezoneResolvesRatherThanMatchesShape is the point of the embedded
// tzdata import: a name that LOOKS like a zone and is not one must be refused,
// or every timestamp renders in UTC forever while the field looks configured.
func TestParseTimezoneResolvesRatherThanMatchesShape(t *testing.T) {
	t.Parallel()

	for _, zone := range []string{"UTC", "Europe/Berlin", "America/Argentina/Buenos_Aires"} {
		t.Run("accepts/"+zone, func(t *testing.T) {
			t.Parallel()
			if _, err := domain.ParseTimezone(zone); err != nil {
				t.Fatalf("ParseTimezone(%q) = %v; the IANA database is embedded, so this "+
					"answer must not depend on the host", zone, err)
			}
		})
	}

	refused := map[string]string{
		"":                 "empty is not a zone; removal is a different request",
		"Europe/Berlim":    "a typo that a shape-only check would accept, rendering every time in UTC",
		"+01:00":           "an offset is what a zone was at one instant, and is wrong for half of every year",
		"Local":            "means the SERVER's zone, so it changes with a deployment (ADR-035)",
		"../../etc/passwd": "a path, and the zone name reaches time.LoadLocation which reads files",
	}
	for zone, why := range refused {
		t.Run("refuses/"+zone, func(t *testing.T) {
			t.Parallel()
			if _, err := domain.ParseTimezone(zone); err == nil {
				t.Fatalf("ParseTimezone(%q) was accepted, want a refusal (%s)", zone, why)
			} else if !errors.Is(err, domain.ErrTimezoneRefused) {
				t.Fatalf("ParseTimezone(%q) = %v, want it to wrap ErrTimezoneRefused", zone, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The aggregate
// ---------------------------------------------------------------------------

func recorded(t *testing.T, p *domain.Profile) *contract.ProfileUpdated {
	t.Helper()
	events := p.Uncommitted()
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want exactly one: a save is ONE fact, and splitting "+
			"it makes a half-applied profile representable in the log", len(events))
	}
	e, ok := events[0].(*contract.ProfileUpdated)
	if !ok {
		t.Fatalf("recorded %T, want *contract.ProfileUpdated", events[0])
	}
	return e
}

// TestUpdateRecordsOneEventForSeveralFields is the "one event, sparse payload"
// decision, asserted rather than documented.
func TestUpdateRecordsOneEventForSeveralFields(t *testing.T) {
	t.Parallel()

	p := domain.NewProfile()
	set := true
	err := p.Update(subject, domain.Update{
		DisplayName: &set,
		Locale:      &set,
		Timezone:    &set,
		Avatar: &domain.Avatar{
			ObjectKey: "avatarx/aaaaaaaaaaaaaaaaaaaaaaaaaa", ContentType: "image/png", SizeBytes: 10,
		},
	}, at())
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	e := recorded(t, p)
	for _, f := range []struct {
		name string
		got  *contract.Change
	}{
		{"DisplayName", e.DisplayName}, {"Locale", e.Locale}, {"Timezone", e.Timezone},
	} {
		if f.got == nil || *f.got != contract.Set {
			t.Fatalf("%s = %v, want Set", f.name, f.got)
		}
	}
	if e.Avatar == nil || e.Avatar.Change != contract.Set {
		t.Fatalf("Avatar = %v, want a Set change", e.Avatar)
	}
}

// TestUpdateLeavesAbsentFieldsNil is the whole sparse contract: a field the
// caller did not name must be nil on the event, because nil is what the
// projection reads as "leave the column alone".
//
// If this ever fails, the projection's COALESCE receives a value instead of
// NULL and every partial save silently erases the fields it did not mention.
func TestUpdateLeavesAbsentFieldsNil(t *testing.T) {
	t.Parallel()

	p := domain.NewProfile()
	set := true
	if err := p.Update(subject, domain.Update{Locale: &set}, at()); err != nil {
		t.Fatalf("Update: %v", err)
	}

	e := recorded(t, p)
	if e.Locale == nil {
		t.Fatal("Locale is nil, but the caller named it")
	}
	if e.DisplayName != nil {
		t.Fatalf("DisplayName = %v; the caller did not name it, so it must be nil — a "+
			"non-nil marker here is a save that erases a name nobody touched", *e.DisplayName)
	}
	if e.Timezone != nil {
		t.Fatalf("Timezone = %v; the caller did not name it, so it must be nil", *e.Timezone)
	}
	if e.Avatar != nil {
		t.Fatalf("Avatar = %+v; the caller did not name it, so it must be nil", e.Avatar)
	}
}

// TestUpdateCarriesNoNameValue is the ADR-002 assertion, made against the
// payload's TYPE rather than its contents: there is no field on
// contract.ProfileUpdated that could hold a display name, so a name cannot
// reach the log even by accident.
func TestUpdateCarriesNoNameValue(t *testing.T) {
	t.Parallel()

	p := domain.NewProfile()
	set := true
	if err := p.Update(subject, domain.Update{DisplayName: &set}, at()); err != nil {
		t.Fatalf("Update: %v", err)
	}
	e := recorded(t, p)

	// The marker says the name changed; nothing says what to.
	if e.DisplayName == nil || *e.DisplayName != contract.Set {
		t.Fatalf("DisplayName = %v, want Set", e.DisplayName)
	}
	// The only string on the payload is the pseudonym and the avatar's key.
	if e.SubjectID != subject {
		t.Fatalf("SubjectID = %q, want the pseudonym %q", e.SubjectID, subject)
	}
	if e.Avatar != nil {
		t.Fatalf("Avatar = %+v, want nil", e.Avatar)
	}
}

// TestUpdateDistinguishesClearedFromAbsent is the second half of the sparse
// contract, and the half a shape without pointers cannot express.
func TestUpdateDistinguishesClearedFromAbsent(t *testing.T) {
	t.Parallel()

	p := domain.NewProfile()
	p.Apply(&contract.ProfileUpdated{
		SubjectID: subject,
		Avatar: &contract.AvatarChange{
			Change: contract.Set, ObjectKey: "avatarx/aaaaaaaaaaaaaaaaaaaaaaaaaa",
			ContentType: "image/png", SizeBytes: 10,
		},
	})

	// Removing it: a non-nil pointer to a ZERO avatar.
	if err := p.Update(subject, domain.Update{Avatar: &domain.Avatar{}}, at()); err != nil {
		t.Fatalf("Update: %v", err)
	}
	e := recorded(t, p)
	if e.Avatar == nil || e.Avatar.Change != contract.Cleared {
		t.Fatalf("Avatar = %+v, want a Cleared change", e.Avatar)
	}
	if e.Avatar.ObjectKey != "" || e.Avatar.ContentType != "" || e.Avatar.SizeBytes != 0 {
		t.Fatalf("Avatar = %+v; a cleared change carries no reference, and the table's "+
			"CHECK constraint refuses a partial one", e.Avatar)
	}
}

func TestUpdateRecordsNothingWhenNothingChanged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		seed   func(*domain.Profile)
		update domain.Update
		why    string
	}{
		{
			name:   "removing an avatar that is not there",
			seed:   func(*domain.Profile) {},
			update: domain.Update{Avatar: &domain.Avatar{}},
			why:    "the caller wanted it gone and it is gone; an event would record no change",
		},
		{
			name: "confirming the avatar key already stored",
			seed: func(p *domain.Profile) {
				p.Apply(&contract.ProfileUpdated{SubjectID: subject, Avatar: &contract.AvatarChange{
					Change: contract.Set, ObjectKey: "avatarx/aaaaaaaaaaaaaaaaaaaaaaaaaa",
					ContentType: "image/png", SizeBytes: 10,
				}})
			},
			update: domain.Update{Avatar: &domain.Avatar{
				ObjectKey: "avatarx/aaaaaaaaaaaaaaaaaaaaaaaaaa", ContentType: "image/png", SizeBytes: 10,
			}},
			why: "a retried confirm, or a second tab; recording it twice would make the " +
				"log a history of saves rather than of changes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := domain.NewProfile()
			tt.seed(p)
			if err := p.Update(subject, tt.update, at()); err != nil {
				t.Fatalf("Update: %v", err)
			}
			if n := len(p.Uncommitted()); n != 0 {
				t.Fatalf("recorded %d events, want none (%s)", n, tt.why)
			}
		})
	}
}

// TestUpdateAlwaysRecordsAVaultFieldBeingSet documents the asymmetry rather
// than leaving it to be rediscovered: the aggregate cannot compare vault values
// because it never sees one, so re-supplying a name records the change.
func TestUpdateAlwaysRecordsAVaultFieldBeingSet(t *testing.T) {
	t.Parallel()

	p := domain.NewProfile()
	p.Apply(&contract.ProfileUpdated{SubjectID: subject, DisplayName: changePtr(contract.Set)})

	set := true
	if err := p.Update(subject, domain.Update{DisplayName: &set}, at()); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if n := len(p.Uncommitted()); n != 1 {
		t.Fatalf("recorded %d events, want one: the value may differ and this package "+
			"must never see it, so the honest answer is to record the save", n)
	}
}

func TestUpdateRefusals(t *testing.T) {
	t.Parallel()

	t.Run("an update that names nothing", func(t *testing.T) {
		t.Parallel()
		p := domain.NewProfile()
		err := p.Update(subject, domain.Update{}, at())
		if !errors.Is(err, domain.ErrNothingToUpdate) {
			t.Fatalf("Update = %v, want ErrNothingToUpdate", err)
		}
	})

	t.Run("a stream belonging to somebody else", func(t *testing.T) {
		t.Parallel()
		p := domain.NewProfile()
		p.Apply(&contract.ProfileUpdated{SubjectID: "subj_01BX5ZZKBKACTAV9WEVGEMMVRZ"})

		set := true
		err := p.Update(subject, domain.Update{DisplayName: &set}, at())
		if !errors.Is(err, domain.ErrWrongSubject) {
			t.Fatalf("Update = %v, want ErrWrongSubject: the alternative writes one "+
				"person's profile into another person's stream", err)
		}
	})

	t.Run("no subject at all", func(t *testing.T) {
		t.Parallel()
		p := domain.NewProfile()
		set := true
		if err := p.Update("", domain.Update{DisplayName: &set}, at()); err == nil {
			t.Fatal("Update with no subject was accepted")
		}
	})
}

// TestApplyIsSparseToo is the read half of the same rule. A replay of an event
// that mentions one field must leave the others where they were, or a rebuild
// produces a different profile from the one the log describes.
func TestApplyIsSparseToo(t *testing.T) {
	t.Parallel()

	p := domain.NewProfile()
	p.Apply(&contract.ProfileUpdated{
		SubjectID:   subject,
		DisplayName: changePtr(contract.Set),
		Locale:      changePtr(contract.Set),
		Avatar: &contract.AvatarChange{
			Change: contract.Set, ObjectKey: "avatarx/aaaaaaaaaaaaaaaaaaaaaaaaaa",
			ContentType: "image/png", SizeBytes: 10,
		},
	})
	// A second event mentioning only the timezone.
	p.Apply(&contract.ProfileUpdated{SubjectID: subject, Timezone: changePtr(contract.Set)})

	switch {
	case !p.HasDisplayName():
		t.Fatal("the display name was forgotten by an event that did not mention it")
	case !p.HasLocale():
		t.Fatal("the locale was forgotten by an event that did not mention it")
	case !p.HasTimezone():
		t.Fatal("the timezone the second event set was not applied")
	case p.Avatar().IsZero():
		t.Fatal("the avatar was forgotten by an event that did not mention it")
	}

	// And a cleared marker really does clear.
	p.Apply(&contract.ProfileUpdated{SubjectID: subject, Locale: changePtr(contract.Cleared)})
	if p.HasLocale() {
		t.Fatal("a Cleared marker left the locale set")
	}
}

// TestNewProfileIsPositionedBeforeItsFirstEvent is what makes the append
// precondition NoStream for a first save, which is in turn what makes two
// concurrent first saves collide instead of both landing.
func TestNewProfileIsPositionedBeforeItsFirstEvent(t *testing.T) {
	t.Parallel()

	agg := eventsourcing.NewAggregate(domain.NewProfile)
	if !eventsourcing.IsNew(agg) {
		t.Fatal("a fresh aggregate does not report as new, so its first save would not " +
			"use the NoStream precondition")
	}
	if got := eventsourcing.ExpectedFor(agg); !got.IsNoStream() {
		t.Fatalf("ExpectedFor = %v, want no_stream", got)
	}
}

func changePtr(c contract.Change) *contract.Change { return &c }
