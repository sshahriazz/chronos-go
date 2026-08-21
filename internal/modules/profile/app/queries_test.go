package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/profile/app"
	"github.com/chronos/chronos-go/internal/modules/profile/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// TestGetAssemblesTheProfileFromBothStores — the projection holds the facts, the
// vault holds the values, and this is the only place they meet.
func TestGetAssemblesTheProfileFromBothStores(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.vault.values[pii.FieldName] = "Ada Lovelace"
	h.vault.values[pii.FieldLocale] = "en-GB"
	h.vault.values[pii.FieldTimezone] = "Europe/London"
	h.reader.view = app.View{
		Exists: true, SubjectID: subject, DisplayNameSet: true,
		Avatar: domain.Avatar{
			ObjectKey: "avatarx/aaaaaaaaaaaaaaaaaaaaaaaaaa", ContentType: "image/png", SizeBytes: 99,
		},
	}

	got, err := h.queries.Get(context.Background(), subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	switch {
	case got.DisplayName != "Ada Lovelace":
		t.Fatalf("DisplayName = %q", got.DisplayName)
	case got.Locale != "en-GB":
		t.Fatalf("Locale = %q", got.Locale)
	case got.Timezone != "Europe/London":
		t.Fatalf("Timezone = %q", got.Timezone)
	case got.Avatar.SizeBytes != 99 || got.Avatar.ContentType != "image/png":
		t.Fatalf("Avatar = %+v", got.Avatar)
	}

	// A URL, never bytes, and never the raw key on its own.
	if !strings.Contains(got.Avatar.URL, "signed") {
		t.Fatalf("Avatar.URL = %q, want a signed URL: a bucket that serves anonymous "+
			"reads has moved authorisation to whoever holds the link", got.Avatar.URL)
	}
	if got.Avatar.URLExpires.IsZero() {
		t.Fatal("the client is not told when the URL stops working, so it will cache a " +
			"link that becomes a broken image")
	}
}

// TestGetTreatsAnErasedSubjectAsEmptyRatherThanAsAFailure
//
// Erasure destroyed the key, so there is nothing left to decrypt. Reporting
// that as an error would make every read of an erased subject a paging alert
// (NOTIFICATIONS §4 takes the same reading).
func TestGetTreatsAnErasedSubjectAsEmptyRatherThanAsAFailure(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		setup func(*fakeVault)
		why   string
	}{
		{"erased", func(v *fakeVault) { v.erased = true }, "the key is gone; there is no name"},
		{"never stored", func(v *fakeVault) { v.absent = true }, "an account that never set one"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			tt.setup(h.vault)
			h.reader.view = app.View{Exists: true, SubjectID: subject}

			got, err := h.queries.Get(context.Background(), subject)
			if err != nil {
				t.Fatalf("Get = %v, want an empty profile (%s)", err, tt.why)
			}
			if got.DisplayName != "" || got.Locale != "" || got.Timezone != "" {
				t.Fatalf("Get returned values for a subject with none: %+v", got)
			}
		})
	}
}

// TestGetDoesNotReportAnUnreachableVaultAsAnEmptyName is the other side of the
// same coin, and the one that matters more: an outage must NOT render as "this
// person removed their name".
func TestGetDoesNotReportAnUnreachableVaultAsAnEmptyName(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.vault.readErr = errors.New("dial tcp: connection refused")
	h.reader.view = app.View{Exists: true, SubjectID: subject}

	_, err := h.queries.Get(context.Background(), subject)
	if err == nil {
		t.Fatal("an unreachable vault produced a profile with no name, which a client " +
			"would render as a profile whose name was removed")
	}
	if reason := errs.ReasonOf(err); reason != errs.Internal {
		t.Fatalf("reason = %s, want %s", reason, errs.Internal)
	}
	// The OUTWARD message, which is what srvconnect.Error puts on the wire — not
	// Error(), which deliberately carries the internal chain onward for logs.
	domainErr, ok := errs.As(err)
	if !ok {
		t.Fatalf("Get returned %T, want an *errs.Error", err)
	}
	if strings.Contains(domainErr.Message, "connection refused") {
		t.Fatalf("the outward message is %q; errors are opaque and driver text goes to "+
			"logs correlated by trace id (ADR-015)", domainErr.Message)
	}
}

// TestGetReturnsAnEmptyProfileForAnAccountThatHasNeverConfiguredAnything
//
// Every account has a profile in the sense that matters: it simply holds
// nothing. NOT_FOUND here would make every client branch on a distinction that
// is not one.
func TestGetReturnsAnEmptyProfileForAnAccountThatHasNeverConfiguredAnything(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.vault.absent = true
	h.reader.view = app.View{} // no row at all

	got, err := h.queries.Get(context.Background(), subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.SubjectID != subject {
		t.Fatalf("SubjectID = %q, want the caller's own", got.SubjectID)
	}
	if !got.Avatar.IsZero() || !got.UpdatedAt.IsZero() {
		t.Fatalf("Get = %+v, want an empty profile", got)
	}
}

// TestGetFailsRatherThanSilentlyDroppingAnAvatarItCannotSign
//
// Presigning is a LOCAL operation, so a failure here is a bug in this server
// rather than an outage in the object store. Degrading to "no avatar" would
// hide it behind a perfectly plausible-looking profile.
func TestGetFailsRatherThanSilentlyDroppingAnAvatarItCannotSign(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.store.signErr = errors.New("bad expiry")
	h.reader.view = app.View{
		Exists: true, SubjectID: subject,
		Avatar: domain.Avatar{ObjectKey: "avatarx/a", ContentType: "image/png", SizeBytes: 1},
	}

	if _, err := h.queries.Get(context.Background(), subject); err == nil {
		t.Fatal("a profile came back with the avatar quietly missing")
	}
}

func TestGetRefusesWithoutASubject(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	if _, err := h.queries.Get(context.Background(), ""); err == nil {
		t.Fatal("a profile read with no subject was accepted; the empty predicate matches " +
			"nothing, which reads as an empty profile rather than as a bug")
	}
}

func TestConstructorsRefusePartialWiring(t *testing.T) {
	t.Parallel()

	if _, err := app.NewQueries(app.QueriesDeps{}); err == nil {
		t.Fatal("NewQueries accepted no dependencies; a nil here panics on the first " +
			"request, after the composition root reported a healthy start")
	}
	if _, err := app.NewUpdates(app.UpdatesDeps{}); err == nil {
		t.Fatal("NewUpdates accepted no dependencies")
	}
	if _, err := app.NewAvatars(app.AvatarsDeps{}); err == nil {
		t.Fatal("NewAvatars accepted no dependencies")
	}
}
