//go:build integration

package protocolit_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/errs"
)

// validationCase is one declared protovalidate rule, driven over the wire.
//
// `field` is the name the refusal must NAME. A validation failure that says
// only "invalid argument" costs a client a support ticket to diagnose, and
// CONVENTIONS §7 puts the rule in the .proto precisely so the answer can be
// specific without a handler writing it.
type validationCase struct {
	name      string
	procedure string
	body      string
	auth      bool
	field     string
	rule      string
}

// violations is one case per declared rule kind across the three services:
// `required`, `min_len`, `max_len`, `pattern`, `gte`/`lte`, `gt`, `in`, `const`,
// `min_items`, `unique`, `enum.not_in`, and a CEL expression.
//
// Every case is traced to a line of .proto AND to the generated descriptor the
// server actually serves, which is not the same thing: `gen/` is a build
// artefact and can lag `proto/`. While this package was being written,
// `AuthenticateRequest.device_id` carried
// `pattern: "^[\x20-\x7E]*$"` in the schema and `string:{max_len:128}` alone in
// the descriptor, so the rule was declared and enforced nowhere. That case was
// removed rather than asserted, because the tree was mid-edit and `make api` had
// not run — but the shape of it is worth stating: a rule that exists only in the
// .proto is a comment, and nothing in the build compares the two.
func violations() []validationCase {
	longIdentifier := strings.Repeat("a", 250) + "@example.test" // 263 bytes
	return []validationCase{
		{
			name:      "Register/email required",
			procedure: "/chronos.identity.v1.IdentityService/Register",
			body:      `{}`,
			field:     "email",
			rule:      "required: true",
		},
		{
			name:      "Register/email has no domain",
			procedure: "/chronos.identity.v1.IdentityService/Register",
			body:      `{"email":"ada-at-example"}`,
			field:     "email",
			rule:      "cel identity.email.shape",
		},
		{
			name:      "ResendEmailVerification/email has no dot in the domain",
			procedure: "/chronos.identity.v1.IdentityService/ResendEmailVerification",
			body:      `{"email":"ada@example"}`,
			field:     "email",
			rule:      "cel identity.email.shape",
		},
		{
			name:      "RequestPasswordReset/local part over 64 bytes",
			procedure: "/chronos.identity.v1.IdentityService/RequestPasswordReset",
			body:      fmt.Sprintf(`{"email":%q}`, strings.Repeat("a", 65)+"@example.test"),
			field:     "email",
			rule:      "cel identity.email.local_part",
		},
		{
			name:      "CheckUsernameAvailability/username too short",
			procedure: "/chronos.identity.v1.IdentityService/CheckUsernameAvailability",
			body:      `{"username":"ab"}`,
			field:     "username",
			rule:      "string.min_len: 3",
		},
		{
			name:      "CheckUsernameAvailability/username starts with an underscore",
			procedure: "/chronos.identity.v1.IdentityService/CheckUsernameAvailability",
			body:      `{"username":"_ada"}`,
			field:     "username",
			rule:      "string.pattern",
		},
		{
			name:      "VerifyEmail/token required",
			procedure: "/chronos.identity.v1.IdentityService/VerifyEmail",
			body:      `{"token":"","password":"correct-horse","username":"ada_lovelace"}`,
			field:     "token",
			rule:      "required: true",
		},
		{
			name:      "ResetPassword/password under 8 characters",
			procedure: "/chronos.identity.v1.IdentityService/ResetPassword",
			body:      `{"token":"anything","password":"short"}`,
			field:     "password",
			rule:      "string.min_len: 8",
		},
		{
			name:      "CreateSession/identifier over 254 bytes",
			procedure: "/chronos.identity.v1.IdentityService/CreateSession",
			body:      fmt.Sprintf(`{"identifier":%q,"password":"correct-horse"}`, longIdentifier),
			field:     "identifier",
			rule:      "cel identity.identifier.length",
		},
		// --- the seven RPCs that declared rules with no wire case ------------
		//
		// Each of these messages carried enforceable protovalidate rules that
		// nothing on the wire had ever tripped. A rule with no case is indistinguishable
		// from a rule that is not enforced, which is the failure the whole table
		// exists to catch — and it had already happened once here, to
		// AuthenticateRequest.device_id.
		{
			name:      "Authenticate/identifier over 254 bytes",
			procedure: "/chronos.identity.v1.IdentityService/Authenticate",
			body:      fmt.Sprintf(`{"identifier":%q,"password":"correct-horse-battery"}`, longIdentifier),
			field:     "identifier",
			rule:      "cel identity.identifier.length",
		},
		{
			// The case this table's own comment records as REMOVED, restored.
			//
			// `device_id` carried `pattern: "^[\x20-\x7E]*$"` in the .proto and
			// `string:{max_len:128}` alone in the generated descriptor, so the rule
			// was declared and enforced nowhere. It was dropped rather than asserted
			// because the tree was mid-edit. `make api` has since run, so the two
			// agree — and this case is what keeps them agreeing. If it fails, the
			// descriptor has drifted from the schema again and every published bound
			// on this field is a claim the server does not keep.
			name:      "Authenticate/a control character in device_id",
			procedure: "/chronos.identity.v1.IdentityService/Authenticate",
			body:      `{"identifier":"ada@example.test","password":"correct-horse-battery","deviceId":"dev\u0007bell"}`,
			field:     "device_id",
			rule:      "string.pattern ^[\\x20-\\x7E]$ — printable ASCII only",
		},
		{
			name:      "GenerateRecoveryCodes/count above the ceiling",
			procedure: "/chronos.identity.v1.IdentityService/GenerateRecoveryCodes",
			body:      `{"count":21}`,
			auth:      true,
			field:     "count",
			rule:      "int32.lte: 20",
		},
		{
			name:      "ListLoginHistory/negative page size",
			procedure: "/chronos.identity.v1.IdentityService/ListLoginHistory",
			body:      `{"pageSize":-1}`,
			auth:      true,
			field:     "page_size",
			rule:      "int32.gte: 0",
		},
		{
			name:      "ListLoginHistory/a page token outside the cursor alphabet",
			procedure: "/chronos.identity.v1.IdentityService/ListLoginHistory",
			body:      `{"pageToken":"not a cursor!"}`,
			auth:      true,
			field:     "page_token",
			rule:      "string.pattern ^[A-Za-z0-9_-]*$",
		},
		{
			name:      "RevokeAllSessions/free text in reason",
			procedure: "/chronos.identity.v1.IdentityService/RevokeAllSessions",
			body:      `{"reason":"Alice asked me to sign out everywhere"}`,
			auth:      true,
			field:     "reason",
			rule:      "string.pattern ^$|^[a-z][a-z0-9_]*$ — free text is where personal data arrives (ADR-002)",
		},
		{
			name:      "RevokeAllSessions/except_session_id is not a prefixed ULID",
			procedure: "/chronos.identity.v1.IdentityService/RevokeAllSessions",
			body:      `{"exceptSessionId":"sess_not_a_ulid","reason":"user_signed_out"}`,
			auth:      true,
			field:     "except_session_id",
			rule:      "string.pattern ^$|^sess_[0-7][0-9A-HJKMNP-TV-Z]{25}$",
		},
		{
			name:      "GetNotificationPreferences/org_id is not a prefixed ULID",
			procedure: "/chronos.notification.v1.NotificationService/GetNotificationPreferences",
			body:      `{"orgId":"acme"}`,
			auth:      true,
			field:     "org_id",
			rule:      "string.pattern ^org_[0-7][0-9A-HJKMNP-TV-Z]{25}$",
		},
		{
			name:      "GetUnreadCount/org_id is not a prefixed ULID",
			procedure: "/chronos.notification.v1.NotificationService/GetUnreadCount",
			body:      `{"orgId":"acme"}`,
			auth:      true,
			field:     "org_id",
			rule:      "string.pattern ^org_[0-7][0-9A-HJKMNP-TV-Z]{25}$",
		},
		{
			name:      "RemovePushSubscription/a plaintext endpoint",
			procedure: "/chronos.notification.v1.NotificationService/RemovePushSubscription",
			body:      fmt.Sprintf(`{"orgId":%q,"endpoint":"http://push.example.test/x"}`, syntheticOrgID),
			auth:      true,
			field:     "endpoint",
			rule:      "string.pattern ^https:// — a push endpoint is a capability URL",
		},
		{
			name:      "ListSessions/negative page size",
			procedure: "/chronos.identity.v1.IdentityService/ListSessions",
			body:      `{"pageSize":-1}`,
			auth:      true,
			field:     "page_size",
			rule:      "int32.gte: 0",
		},
		{
			name:      "ConfirmTotp/code required",
			procedure: "/chronos.identity.v1.IdentityService/ConfirmTotp",
			body:      `{"code":""}`,
			auth:      true,
			field:     "code",
			rule:      "required: true",
		},
		{
			name:      "RevokeSession/session id is not a prefixed ULID",
			procedure: "/chronos.identity.v1.IdentityService/RevokeSession",
			body:      `{"sessionId":"not-a-session"}`,
			auth:      true,
			field:     "session_id",
			rule:      "string.pattern ^sess_…$",
		},
		{
			name:      "RevokeSession/free text in reason",
			procedure: "/chronos.identity.v1.IdentityService/RevokeSession",
			body: `{"sessionId":"sess_01ARZ3NDEKTSV4RRFFQ69G5FAV",` +
				`"reason":"Alice asked me to sign out her iPhone"}`,
			auth:  true,
			field: "reason",
			rule:  "string.pattern ^$|^[a-z][a-z0-9_]*$ — free text is where personal data arrives (ADR-002)",
		},
		{
			name:      "RequestAccountDeletion/confirmation must be the literal DELETE",
			procedure: "/chronos.identity.v1.IdentityService/RequestAccountDeletion",
			body:      `{"confirmation":"delete"}`,
			auth:      true,
			field:     "confirmation",
			rule:      `string.const: "DELETE"`,
		},
		{
			name:      "ListNotifications/org id is not a prefixed ULID",
			procedure: "/chronos.notification.v1.NotificationService/ListNotifications",
			body:      `{"orgId":"acme"}`,
			auth:      true,
			field:     "org_id",
			rule:      "string.pattern ^org_…$",
		},
		{
			name:      "ListNotifications/page size over the ceiling",
			procedure: "/chronos.notification.v1.NotificationService/ListNotifications",
			body:      fmt.Sprintf(`{"orgId":%q,"pageSize":5000}`, syntheticOrgID),
			auth:      true,
			field:     "page_size",
			rule:      "int32.lte: 1000",
		},
		{
			name:      "MarkNotificationsRead/an empty batch",
			procedure: "/chronos.notification.v1.NotificationService/MarkNotificationsRead",
			body:      fmt.Sprintf(`{"orgId":%q,"notificationIds":[]}`, syntheticOrgID),
			auth:      true,
			field:     "notification_ids",
			rule:      "repeated.min_items: 1",
		},
		{
			name:      "MarkNotificationsRead/the same id twice",
			procedure: "/chronos.notification.v1.NotificationService/MarkNotificationsRead",
			body: fmt.Sprintf(`{"orgId":%q,"notificationIds":`+
				`["notif_01ARZ3NDEKTSV4RRFFQ69G5FAV","notif_01ARZ3NDEKTSV4RRFFQ69G5FAV"]}`,
				syntheticOrgID),
			auth:  true,
			field: "notification_ids",
			rule:  "repeated.unique: true",
		},
		{
			name:      "RegisterPushSubscription/a plaintext endpoint",
			procedure: "/chronos.notification.v1.NotificationService/RegisterPushSubscription",
			body: fmt.Sprintf(`{"orgId":%q,"endpoint":"http://push.example.test/x",`+
				`"p256dh":%q,"auth":%q}`, syntheticOrgID, pushP256DH, pushAuth),
			auth:  true,
			field: "endpoint",
			rule:  "string.pattern ^https://",
		},
		{
			name:      "SetNotificationPreferences/one channel listed twice",
			procedure: "/chronos.notification.v1.NotificationService/SetNotificationPreferences",
			body: fmt.Sprintf(`{"orgId":%q,"channels":[`+
				`{"channel":"CHANNEL_EMAIL","enabled":true},`+
				`{"channel":"CHANNEL_EMAIL","enabled":false}]}`, syntheticOrgID),
			auth:  true,
			field: "channels",
			rule:  "cel notification.preferences.one_entry_per_channel",
		},
		{
			name:      "SetNotificationPreferences/an unspecified channel",
			procedure: "/chronos.notification.v1.NotificationService/SetNotificationPreferences",
			body: fmt.Sprintf(`{"orgId":%q,"channels":[`+
				`{"channel":"CHANNEL_UNSPECIFIED","enabled":true}]}`, syntheticOrgID),
			auth:  true,
			field: "channel",
			rule:  "enum.not_in: [0]",
		},
		{
			name:      "UpdateProfile/an empty display name",
			procedure: "/chronos.profile.v1.ProfileService/UpdateProfile",
			body:      `{"displayName":""}`,
			auth:      true,
			field:     "display_name",
			rule:      "string.min_len: 1 — clearing a name is not spelled with an empty string",
		},
		{
			name:      "UpdateProfile/a display name with leading whitespace",
			procedure: "/chronos.profile.v1.ProfileService/UpdateProfile",
			body:      `{"displayName":" Ada"}`,
			auth:      true,
			field:     "display_name",
			rule:      `string.pattern ^\S(.*\S)?$`,
		},
		{
			name:      "UpdateProfile/a locale that is not a BCP-47 tag",
			procedure: "/chronos.profile.v1.ProfileService/UpdateProfile",
			body:      `{"locale":"english"}`,
			auth:      true,
			field:     "locale",
			rule:      "string.pattern",
		},
		{
			name:      "CreateAvatarUpload/an unlisted content type",
			procedure: "/chronos.profile.v1.ProfileService/CreateAvatarUpload",
			body:      `{"contentType":"image/gif","sizeBytes":1024}`,
			auth:      true,
			field:     "content_type",
			rule:      `string.in: [image/png, image/jpeg, image/webp]`,
		},
		{
			name:      "CreateAvatarUpload/a zero-byte upload",
			procedure: "/chronos.profile.v1.ProfileService/CreateAvatarUpload",
			body:      `{"contentType":"image/png","sizeBytes":"0"}`,
			auth:      true,
			field:     "size_bytes",
			rule:      "int64.gt: 0",
		},
		{
			name:      "CreateAvatarUpload/over the five megabyte ceiling",
			procedure: "/chronos.profile.v1.ProfileService/CreateAvatarUpload",
			body:      `{"contentType":"image/png","sizeBytes":"5242881"}`,
			auth:      true,
			field:     "size_bytes",
			rule:      "int64.lte: 5242880",
		},
	}
}

// TestEveryDeclaredRuleIsEnforcedOnTheWire drives one violation per declared
// rule and asserts three things about each refusal: the transport code, the
// machine-readable reason, and that the message NAMES the offending field.
//
// CONVENTIONS §7: "Validation is declarative — protovalidate rules in the
// .proto. Handlers never hand-check required fields." That is only a contract if
// the rules are actually enforced before a handler runs, and the OpenAPI spec
// publishes every one of them to clients.
func TestEveryDeclaredRuleIsEnforcedOnTheWire(t *testing.T) {
	bearer := h.activeBearer(t)

	for _, vc := range violations() {
		t.Run(vc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			token := ""
			if vc.auth {
				token = bearer
			}
			status, body, err := rawPost(ctx, vc.procedure, "application/json",
				vc.body, token, newIdempotencyKey(), nil)
			if err != nil {
				t.Fatalf("POST %s: %v", vc.procedure, err)
			}
			if status != http.StatusBadRequest {
				t.Fatalf("BUG: %s violates `%s` and the server answered %d, not 400. "+
					"An unenforced rule is a comment: the schema documents the constraint "+
					"and the OpenAPI spec publishes it to every client.\n%s",
					vc.name, vc.rule, status, describeRaw(status, body))
			}
			env, derr := decodeWireError(body)
			if derr != nil {
				t.Fatalf("the refusal is not a Connect error envelope: %v\nbody: %s",
					derr, strings.TrimSpace(body))
			}
			if env.Code != "invalid_argument" {
				t.Errorf("%s answered code %q, want invalid_argument (%s)",
					vc.name, env.Code, describeRaw(status, body))
			}
			if !strings.Contains(env.Message, vc.field) {
				t.Errorf("%s: the refusal does not name the offending field %q, so a client "+
					"cannot show the user which input to fix. message: %q",
					vc.name, vc.field, env.Message)
			}
			t.Logf("%s -> %s", vc.name, describeRaw(status, body))
		})
	}
}

// TestAProtovalidateRefusalCarriesTheReasonCode is a DEFECT REPORT.
//
// CONVENTIONS §5 lists `VALIDATION_FAILED` as the reason for "protovalidate or
// domain", and §5.1 and §7.1 both say clients branch on `reason` and NEVER on
// the transport status:
//
// > If those codes are not published, every client hardcodes strings scraped out
// > of live responses, and changing one silently breaks them.
//
// A protovalidate refusal does not carry one. `connectrpc.com/validate` builds
// its own `connect.Error` with a `buf.validate.Violations` detail; it never
// passes through `internal/platform/errs`, and `server/connect.Error` — the only
// place a `chronos.errors.v1.ErrorDetail` is attached — is never called. So the
// half of `InvalidArgument` that comes from the schema is exactly the half a
// client cannot classify, while the half that comes from a handler
// (`errs.ValidationFailedf`) can be.
//
// The consequence is concrete: a client receiving `invalid_argument` has to
// decide between "your input is malformed, show field errors" and "you forgot
// the Idempotency-Key, that is a bug in me" — two completely different
// behaviours behind one status, which is the exact situation §5's reason column
// exists to prevent.
//
// The `buf.validate.Violations` detail IS present and is genuinely useful; this
// is not an argument for removing it. The finding is that the reason is missing
// alongside it.
func TestAProtovalidateRefusalCarriesTheReasonCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	status, body, err := rawPost(ctx, "/chronos.identity.v1.IdentityService/Register",
		"application/json", `{"email":"ada-at-example"}`, "", newIdempotencyKey(), nil)
	if err != nil {
		t.Fatalf("POST Register: %v", err)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("expected a validation refusal, got %s", describeRaw(status, body))
	}

	env, derr := decodeWireError(body)
	if derr != nil {
		t.Fatalf("not a Connect error envelope: %v\nbody: %s", derr, body)
	}

	var kinds []string
	for _, d := range env.Details {
		kinds = append(kinds, d.Type)
	}
	t.Logf("details on a protovalidate refusal: %v", kinds)

	if got := reasonFromJSON(body); got != string(errs.ValidationFailed) {
		t.Errorf("BUG: a protovalidate refusal carries reason %q, want %q.\n"+
			"CONVENTIONS §5 maps protovalidate failures to VALIDATION_FAILED and §5.1 says "+
			"clients branch on the reason and never on the status. "+
			"connectrpc.com/validate builds its own connect.Error and never goes through "+
			"internal/platform/errs, so server/connect.Error — the only place a "+
			"chronos.errors.v1.ErrorDetail is attached — never runs for it. "+
			"Details present: %v", got, errs.ValidationFailed, kinds)
	}
}

// TestInputThatViolatesNothingGetsPastValidation is the other half, and it is
// the half that keeps the tests above honest.
//
// Every case here is well-formed against every declared rule, so the ONLY answer
// it may not receive is `invalid_argument`. What it does receive varies — a
// wrong password is `unauthenticated`, an unknown session is `not_found` — and
// that is the point: those come from a handler, which means validation let the
// request through. Asserting success instead would make this a test of the
// handlers, and a validator that rejected everything would still pass a test
// that only checked for errors.
func TestInputThatViolatesNothingGetsPastValidation(t *testing.T) {
	bearer := h.activeBearer(t)

	cases := []struct {
		name      string
		procedure string
		body      string
		auth      bool
	}{
		{
			name:      "Register/a well-formed address",
			procedure: "/chronos.identity.v1.IdentityService/Register",
			body:      fmt.Sprintf(`{"email":%q}`, h.freshEmail("valid")),
		},
		{
			name:      "CheckUsernameAvailability/a well-formed handle",
			procedure: "/chronos.identity.v1.IdentityService/CheckUsernameAvailability",
			body:      `{"username":"ada_lovelace"}`,
		},
		{
			name:      "VerifyEmail/every field well-formed, token unknown",
			procedure: "/chronos.identity.v1.IdentityService/VerifyEmail",
			body: `{"token":"not-a-real-token","password":"correct-horse-battery",` +
				`"username":"ada_lovelace2"}`,
		},
		{
			name:      "CreateSession/well-formed credentials that are wrong",
			procedure: "/chronos.identity.v1.IdentityService/CreateSession",
			body:      `{"identifier":"nobody@example.test","password":"correct-horse-battery"}`,
		},
		{
			name:      "ListSessions/a page size of zero, which means the default",
			procedure: "/chronos.identity.v1.IdentityService/ListSessions",
			body:      `{"pageSize":0}`,
			auth:      true,
		},
		{
			name:      "RevokeSession/a well-formed id and a snake_case reason",
			procedure: "/chronos.identity.v1.IdentityService/RevokeSession",
			body: `{"sessionId":"sess_01ARZ3NDEKTSV4RRFFQ69G5FAV",` +
				`"reason":"user_signed_out"}`,
			auth: true,
		},
		{
			name:      "MarkNotificationsRead/one well-formed id",
			procedure: "/chronos.notification.v1.NotificationService/MarkNotificationsRead",
			body: fmt.Sprintf(`{"orgId":%q,"notificationIds":`+
				`["notif_01ARZ3NDEKTSV4RRFFQ69G5FAV"]}`, syntheticOrgID),
			auth: true,
		},
		{
			name:      "UpdateProfile/a locale that is a BCP-47 tag",
			procedure: "/chronos.profile.v1.ProfileService/UpdateProfile",
			body:      `{"locale":"en-GB"}`,
			auth:      true,
		},
		{
			name:      "CreateAvatarUpload/a listed content type under the ceiling",
			procedure: "/chronos.profile.v1.ProfileService/CreateAvatarUpload",
			body:      `{"contentType":"image/png","sizeBytes":"1024"}`,
			auth:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			token := ""
			if tc.auth {
				token = bearer
			}
			status, body, err := rawPost(ctx, tc.procedure, "application/json",
				tc.body, token, newIdempotencyKey(), nil)
			if err != nil {
				t.Fatalf("POST %s: %v", tc.procedure, err)
			}
			// A 400 is not automatically a failure here: a HANDLER may legitimately
			// refuse well-formed input — an unknown verification token is
			// `VALIDATION_FAILED` from identity, not from the schema. What must not
			// happen is a PROTOVALIDATE refusal, and the discriminator is the
			// `buf.validate.Violations` detail, which only the validation
			// interceptor attaches. Discriminating on the message text would break
			// the day the wording changes; discriminating on the reason would bake
			// in the missing-reason defect this file also reports.
			if env, derr := decodeWireError(body); derr == nil && hasViolationsDetail(env) {
				t.Fatalf("BUG: %s violates no declared rule and protovalidate refused it: %s\n"+
					"A validator that refuses well-formed input is worse than none — it makes "+
					"the schema unreachable from the outside.", tc.name, env.Message)
			}
			t.Logf("%s -> %s", tc.name, describeRaw(status, body))
		})
	}
}

// hasViolationsDetail reports whether an error carries protovalidate's own
// detail, which is how a schema refusal is told apart from a handler's.
func hasViolationsDetail(env wireError) bool {
	for _, d := range env.Details {
		if strings.HasSuffix(d.Type, "buf.validate.Violations") {
			return true
		}
	}
	return false
}
