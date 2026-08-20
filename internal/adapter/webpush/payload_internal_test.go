package webpush

import (
	"reflect"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// A push payload crosses a THIRD-PARTY service and may render on a lock screen a
// stranger can read. Nothing identifying may be in it (ADR-002,
// notification.md §4).
//
// Asserted on the CONSTRUCTED payload, not on the HTTP body: the body is
// encrypted, so inspecting the request proves nothing about its contents.
func TestBuiltPayloadExcludesTheRecipient(t *testing.T) {
	n := notify.Notification{
		Template: "identity.password_changed",
		Class:    notify.Security,
		Recipient: notify.Recipient{
			SubjectID: "sub_01J8Z9ABCDEF",
			Address:   "sam.larsson@example.test",
			Name:      "Sam Larsson",
		},
		Data:           map[string]any{"Device": "Firefox", "Location": "Berlin"},
		IdempotencyKey: "evt_1:0",
	}

	encoded, err := codec.Marshal(buildPayload(n,
		"Your password was changed", "If this wasn't you, secure your account.",
		"https://app.chronos.test"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(encoded)

	for _, forbidden := range []string{
		"sam.larsson@example.test", // address
		"Sam Larsson",              // name
		"sub_01J8Z9ABCDEF",         // even the pseudonym identifies a person
		"Berlin",                   // location is personal data
		"Firefox",                  // device fingerprinting
	} {
		if strings.Contains(got, forbidden) {
			t.Errorf("the push payload contains %q:\n%s", forbidden, got)
		}
	}

	if !strings.Contains(got, "Your password was changed") {
		t.Errorf("the payload lost its title:\n%s", got)
	}
	if !strings.Contains(got, "evt_1:0") {
		t.Errorf("the payload lost the notification id, so notificationclick cannot mark it read:\n%s", got)
	}
}

// The payload is a closed struct so a field cannot be added casually — and the
// field somebody would add is the recipient's name. This fails the moment the
// shape changes, forcing the privacy question to be answered again.
func TestPayloadShapeIsClosed(t *testing.T) {
	allowed := map[string]struct{}{
		"Title": {}, "Body": {}, "NotificationID": {}, "URL": {},
	}
	ty := reflect.TypeFor[Payload]()
	for field := range ty.Fields() {
		name := field.Name
		if _, ok := allowed[name]; !ok {
			t.Errorf("Payload gained the field %q. A push payload transits a "+
				"third-party service and may render on a lock screen — if this "+
				"field can carry anything identifying, it must not be here "+
				"(ADR-002, notification.md §4)", name)
		}
	}
	if ty.NumField() != len(allowed) {
		t.Errorf("Payload has %d fields, expected %d", ty.NumField(), len(allowed))
	}
}

// The endpoint token identifies a device. It must not reach logs.
func TestEndpointIsRedactedForLogs(t *testing.T) {
	const endpoint = "https://fcm.googleapis.com/fcm/send/cXY9-SECRET-DEVICE-TOKEN"
	got := redactEndpoint(endpoint)
	if strings.Contains(got, "SECRET-DEVICE-TOKEN") {
		t.Fatalf("the device token survived redaction: %s", got)
	}
	if !strings.Contains(got, "fcm.googleapis.com") {
		t.Errorf("the push service host should survive for diagnosis: %s", got)
	}
}
