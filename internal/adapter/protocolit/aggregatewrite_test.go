//go:build integration

package protocolit_test

import (
	"context"
	"strings"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"
	notificationv1 "github.com/chronos/chronos-go/gen/proto/chronos/notification/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/notification/v1/notificationv1connect"
	profilev1 "github.com/chronos/chronos-go/gen/proto/chronos/profile/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/profile/v1/profilev1connect"
	notificationdomain "github.com/chronos/chronos-go/internal/modules/notification/domain"
	"github.com/chronos/chronos-go/internal/modules/profile"
	profiledomain "github.com/chronos/chronos-go/internal/modules/profile/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// TestASecondWriteToAnAggregateIsRefused is a DEFECT REPORT with a reproduction.
//
// # What the server does
//
// `ProfileService/UpdateProfile` and `NotificationService/SetNotificationPreferences`
// each succeed exactly once for a given subject and then fail for the lifetime
// of that account, with:
//
//	internal: reading a profile
//	internal: reading notification preferences
//
// and nothing else on the wire. The cause reaches the log only:
//
//	loading profile-subj_…: eventsourcing: event type "profile.ProfileUpdated.v1" is not registered
//	loading notification-pref…: eventsourcing: event type "notification.ChannelPreferenceSet.v1" is not registered
//
// # Why
//
// cmd/api/deps.go builds ONE codec and ONE upcaster registry for the process and
// fills them from identity alone:
//
//	d.upcasters = eventsourcing.NewUpcasterRegistry()
//	identity.RegisterSchemas(d.upcasters)
//	d.codec = eventcodec.NewJSON(d.upcasters)
//	identity.RegisterEvents(d.codec)
//
// `notification.RegisterEvents` / `RegisterSchemas` and `profile.RegisterEvents`
// / `RegisterSchemas` are never called. cmd/projector calls all six;
// cmd/worker calls identity's and profile's. So the API server can WRITE a
// notification or profile event — appending needs only the type's own name — and
// cannot READ one back, which is what every command does as its first act.
//
// The first write is the exception rather than the reward: an empty stream
// decodes zero events, so `Repository.Load` returns a fresh aggregate and the
// append succeeds. Every write after that has an event to decode.
//
// # Why nothing else catches it
//
// The projector registers everything, so `profile_view`, `notification_pref` and
// every dashboard stay perfectly healthy. `GetProfile` and
// `GetNotificationPreferences` read the PROJECTION and keep answering — this
// test asserts that too, because "the read still works" is exactly what makes
// the write failure look like a client problem.
//
// Both modules already export `EventTypes()` with the comment "exported so a
// composition-root test can assert that what a binary registers and what this
// module publishes are the same set". That test exists for no binary.
//
// # This test is a finding, not a request
//
// It fails until cmd/api registers the other two modules' events and schemas.
// The fix is four lines in cmd/api/deps.go, and it is deliberately NOT made
// here: cmd/api is out of this package's scope.
func TestASecondWriteToAnAggregateIsRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	profileClient := profilev1connect.NewProfileServiceClient(clientFor(false), h.baseURL)
	notifyClient := notificationv1connect.NewNotificationServiceClient(clientFor(false), h.baseURL)

	t.Run("ProfileService/UpdateProfile", func(t *testing.T) {
		// A fresh subject, so "the first one worked" is a statement about this
		// test rather than about whatever ran before it.
		account, err := h.newVerifiedAccount(ctx, "prof")
		if err != nil {
			t.Fatalf("building an account: %v", err)
		}

		for i, tz := range []string{"Europe/London", "Europe/Paris", "Asia/Tokyo"} {
			zone := tz
			req := connectrpc.NewRequest(&profilev1.UpdateProfileRequest{Timezone: &zone})
			stamp(req.Header(), account.bearer, newIdempotencyKey())
			_, err := profileClient.UpdateProfile(ctx, req)
			if err == nil {
				t.Logf("update %d (timezone=%s) succeeded", i+1, tz)
				continue
			}
			t.Errorf("BUG: update %d (timezone=%s) failed: %s\n"+
				"cmd/api never calls profile.RegisterEvents, so the API server can append "+
				"profile.ProfileUpdated.v1 and cannot decode it. Every profile edit after "+
				"the first is permanently INTERNAL for this account.", i+1, tz, describe(err))
		}

		// The read still answers, which is what makes this so quiet: the
		// projector has its own codec and its own registration, so the settings
		// screen renders the value the first write stored while every later save
		// fails.
		got, err := profileClient.GetProfile(ctx,
			authed(&profilev1.GetProfileRequest{}, account.bearer))
		if err != nil {
			t.Fatalf("GetProfile: %s", describe(err))
		}
		t.Logf("GetProfile still answers: timezone=%q", got.Msg.GetTimezone())
	})

	t.Run("NotificationService/SetNotificationPreferences", func(t *testing.T) {
		account, err := h.newVerifiedAccount(ctx, "pref")
		if err != nil {
			t.Fatalf("building an account: %v", err)
		}

		for i, enabled := range []bool{false, true, false} {
			req := connectrpc.NewRequest(&notificationv1.SetNotificationPreferencesRequest{
				OrgId: syntheticOrgID,
				Channels: []*notificationv1.ChannelPreference{
					{Channel: notificationv1.Channel_CHANNEL_EMAIL, Enabled: enabled},
				},
			})
			stamp(req.Header(), account.bearer, newIdempotencyKey())
			_, err := notifyClient.SetNotificationPreferences(ctx, req)
			if err == nil {
				t.Logf("set %d (email=%t) succeeded", i+1, enabled)
				continue
			}
			t.Errorf("BUG: set %d (email=%t) failed: %s\n"+
				"cmd/api never calls notification.RegisterEvents, so every change to a "+
				"channel toggle after the first is permanently INTERNAL for this account.",
				i+1, enabled, describe(err))
		}
	})

	if strings.Contains(h.serverLogs(), "is not registered") {
		t.Logf("the server named the cause in its own log, which is the one thing that "+
			"went right here:\n%s", extractLines(h.serverLogs(), "is not registered"))
	}
}

// TestEventsWrittenByTheAPIServerCarryTheirSchemaVersion is the SECOND half of
// the same defect, and it outlives the first.
//
// cmd/api's upcaster registry is filled by `identity.RegisterSchemas` alone, so
// `eventsourcing.StampSchemaVersion` has no version to stamp for a notification
// or profile event and leaves the metadata at 0. `notification.RegisterSchemas`
// and `profile.RegisterSchemas` both declare v1.
//
// That matters AFTER the registration above is fixed. An event stored at
// version 0 is a version the registry believes is older than current, and
// loading it demands a v0 → v1 upcaster that does not exist and should not —
// the shape never changed. So every profile and preference event this build has
// already written stays unloadable, and adding the four missing lines to
// cmd/api produces a system that still cannot read its own back catalogue.
//
// This is the identical defect identityit found for identity events
// (TestIdentityEventsCarryTheirSchemaVersion), on the two modules that were
// added afterwards.
func TestEventsWrittenByTheAPIServerCarryTheirSchemaVersion(t *testing.T) {
	bearer := h.activeBearer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	// One write of each kind, through the public API, on the shared account —
	// its first write of each has probably already happened, which is fine: the
	// question is what is IN the stream, not who put it there.
	zone := "Pacific/Auckland"
	req := connectrpc.NewRequest(&profilev1.UpdateProfileRequest{Timezone: &zone})
	stamp(req.Header(), bearer, newIdempotencyKey())
	_, _ = profilev1connect.NewProfileServiceClient(clientFor(false), h.baseURL).
		UpdateProfile(ctx, req)

	upcasters := eventsourcing.NewUpcasterRegistry()
	profile.RegisterSchemas(upcasters)

	stream, err := eventsourcing.NewStreamID(profiledomain.Category, h.active.subjectID)
	if err != nil {
		t.Fatalf("stream id: %v", err)
	}
	events, err := h.store.ReadStream(ctx, stream, 0)
	if err != nil {
		t.Fatalf("reading %s: %v", stream, err)
	}
	if len(events) == 0 {
		t.Skipf("%s is empty, so there is no stored event to inspect; the write above "+
			"was refused and TestASecondWriteToAnAggregateIsRefused is the report", stream)
	}

	for _, e := range events {
		meta, err := h.codec.UnmarshalMetadata(e.Metadata)
		if err != nil {
			t.Fatalf("metadata of %s: %v", e.Type, err)
		}
		want, ok := upcasters.CurrentVersion(e.Type)
		if !ok {
			t.Errorf("%s is not in profile's own schema registry", e.Type)
			continue
		}
		if meta.SchemaVersion != want {
			t.Errorf("BUG: %s on %s was stored at schema_version %d, but profile's registry "+
				"declares v%d. Loading it demands a v%d -> v%d upcaster that does not exist "+
				"and should not — the shape never changed. cmd/api never calls "+
				"profile.RegisterSchemas, so StampSchemaVersion had nothing to stamp.",
				e.Type, stream, meta.SchemaVersion, want, meta.SchemaVersion, want)
			continue
		}
		t.Logf("%s stored at schema_version %d (current)", e.Type, meta.SchemaVersion)
	}

	// Named here so the notification half is not silently out of scope: its
	// stream key is a hash the API computes and this package cannot reproduce
	// without duplicating that derivation, which would be a second source of
	// truth for it. The profile stream proves the mechanism; the same registry
	// omission applies to notification's events verbatim.
	t.Logf("notification events (category %q) share the same omission; their stream key "+
		"is derived inside the module, so the mechanism is asserted on profile only",
		notificationdomain.Category)
}

// extractLines returns the lines of s containing needle, for a log excerpt that
// is evidence rather than a wall.
func extractLines(s, needle string) string {
	var out []string
	for line := range strings.SplitSeq(s, "\n") {
		if strings.Contains(line, needle) {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}
