//go:build integration

package protocolit_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	connectrpc "connectrpc.com/connect"
	errorsv1 "github.com/chronos/chronos-go/gen/proto/chronos/errors/v1"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/identity/v1/identityv1connect"
	notificationv1 "github.com/chronos/chronos-go/gen/proto/chronos/notification/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/notification/v1/notificationv1connect"
	profilev1 "github.com/chronos/chronos-go/gen/proto/chronos/profile/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/profile/v1/profilev1connect"
	systemv1 "github.com/chronos/chronos-go/gen/proto/chronos/system/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/system/v1/systemv1connect"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// ---------------------------------------------------------------------------
// the transports this one port carries (ADR-007)
// ---------------------------------------------------------------------------

// transport is one wire format plus the HTTP version it runs on.
//
// The HTTP version is part of the case, not an implementation detail. gRPC
// requires HTTP/2 and there is no ALPN over plaintext, so "the server answers
// gRPC" is really a claim about h2c prior-knowledge upgrades; a client that
// silently fell back to HTTP/1.1 would prove something else entirely.
type transport struct {
	name string
	h2   bool
	opts []connectrpc.ClientOption
}

// transports is the matrix. `connect+get` is separate from `connect` because
// WithHTTPGet changes the HTTP METHOD for NO_SIDE_EFFECTS procedures, which is
// the whole subject of the GET tests — here it proves the generated client's own
// GET form reaches the same handler.
func transports() []transport {
	return []transport{
		{"connect/http1.1", false, nil},
		{"connect/h2c", true, nil},
		{"connect+get/http1.1", false, []connectrpc.ClientOption{connectrpc.WithHTTPGet()}},
		{"grpc/h2c", true, []connectrpc.ClientOption{connectrpc.WithGRPC()}},
		{"grpc-web/http1.1", false, []connectrpc.ClientOption{connectrpc.WithGRPCWeb()}},
		{"grpc-web/h2c", true, []connectrpc.ClientOption{connectrpc.WithGRPCWeb()}},
	}
}

// ---------------------------------------------------------------------------
// the RPC catalogue
// ---------------------------------------------------------------------------

// syntheticOrgID is a well-formed organization id that names no organization.
//
// Every NotificationService RPC declares `org_id` with
// `^org_[0-9ABCDEFGHJKMNPQRSTVWXYZ]{26}$` and protovalidate evaluates the rule
// on the ZERO value too — an implicit-presence scalar has no "unset" — so an
// omitted org_id is a validation failure, not a default. The `organization`
// module does not exist in this build, so there is no real id to send and a
// syntactically valid one is the only kind available. The feed, the unread count
// and the preferences all answer for it: empty, zero, and the defaults.
const syntheticOrgID = "org_01ARZ3NDEKTSV4RRFFQ69G5FAV"

// readCase is one `idempotency_level = NO_SIDE_EFFECTS` RPC.
//
// It carries three descriptions of the same call, because the suite drives it
// three ways: through the generated client (call), through a hand-built Connect
// GET URL (message, the JSON the `message` query parameter carries), and through
// raw HTTP POST (procedure + message). fingerprint reduces the reply to the part
// that must be IDENTICAL across protocols — the wire format may not change the
// answer, but `lastSeenAt` moves on every authenticated request and would make a
// whole-message comparison a test of the clock.
type readCase struct {
	name      string
	procedure string
	public    bool
	message   string
	call      func(ctx context.Context, c *http.Client, bearer string, opts ...connectrpc.ClientOption) (string, error)
}

// reads is every NO_SIDE_EFFECTS RPC the server serves: the eight the OpenAPI
// spec exposes as GET across identity, notification and profile, plus
// SystemService/GetStatus, which is also NO_SIDE_EFFECTS and also gets a GET
// route.
func reads() []readCase {
	return []readCase{
		{
			name:      "SystemService/GetStatus",
			procedure: "/chronos.system.v1.SystemService/GetStatus",
			public:    true,
			message:   `{}`,
			call: func(ctx context.Context, c *http.Client, _ string, opts ...connectrpc.ClientOption) (string, error) {
				res, err := systemv1connect.NewSystemServiceClient(c, h.baseURL, opts...).
					GetStatus(ctx, connectrpc.NewRequest(&systemv1.GetStatusRequest{}))
				if err != nil {
					return "", err
				}
				return fingerprintStatus(res.Msg), nil
			},
		},
		{
			name:      "IdentityService/GetUser",
			procedure: "/chronos.identity.v1.IdentityService/GetUser",
			message:   `{}`,
			call: func(ctx context.Context, c *http.Client, bearer string, opts ...connectrpc.ClientOption) (string, error) {
				res, err := identityv1connect.NewIdentityServiceClient(c, h.baseURL, opts...).
					GetUser(ctx, authed(&identityv1.GetUserRequest{}, bearer))
				if err != nil {
					return "", err
				}
				return fingerprintUser(res.Msg), nil
			},
		},
		{
			name:      "IdentityService/ListSessions",
			procedure: "/chronos.identity.v1.IdentityService/ListSessions",
			message:   `{"pageSize":10}`,
			call: func(ctx context.Context, c *http.Client, bearer string, opts ...connectrpc.ClientOption) (string, error) {
				res, err := identityv1connect.NewIdentityServiceClient(c, h.baseURL, opts...).
					ListSessions(ctx, authed(&identityv1.ListSessionsRequest{PageSize: 10}, bearer))
				if err != nil {
					return "", err
				}
				return fingerprintSessions(res.Msg), nil
			},
		},
		{
			name:      "IdentityService/ListMethods",
			procedure: "/chronos.identity.v1.IdentityService/ListMethods",
			message:   `{}`,
			call: func(ctx context.Context, c *http.Client, bearer string, opts ...connectrpc.ClientOption) (string, error) {
				res, err := identityv1connect.NewIdentityServiceClient(c, h.baseURL, opts...).
					ListMethods(ctx, authed(&identityv1.ListMethodsRequest{}, bearer))
				if err != nil {
					return "", err
				}
				return fingerprintMethods(res.Msg), nil
			},
		},
		{
			name:      "IdentityService/ListLoginHistory",
			procedure: "/chronos.identity.v1.IdentityService/ListLoginHistory",
			message:   `{"pageSize":5}`,
			call: func(ctx context.Context, c *http.Client, bearer string, opts ...connectrpc.ClientOption) (string, error) {
				res, err := identityv1connect.NewIdentityServiceClient(c, h.baseURL, opts...).
					ListLoginHistory(ctx, authed(&identityv1.ListLoginHistoryRequest{PageSize: 5}, bearer))
				if err != nil {
					return "", err
				}
				return fingerprintLoginHistory(res.Msg), nil
			},
		},
		{
			name:      "NotificationService/ListNotifications",
			procedure: "/chronos.notification.v1.NotificationService/ListNotifications",
			message:   fmt.Sprintf(`{"orgId":%q,"pageSize":10}`, syntheticOrgID),
			call: func(ctx context.Context, c *http.Client, bearer string, opts ...connectrpc.ClientOption) (string, error) {
				res, err := notificationv1connect.NewNotificationServiceClient(c, h.baseURL, opts...).
					ListNotifications(ctx, authed(&notificationv1.ListNotificationsRequest{
						OrgId: syntheticOrgID, PageSize: 10,
					}, bearer))
				if err != nil {
					return "", err
				}
				return fingerprintFeed(res.Msg), nil
			},
		},
		{
			name:      "NotificationService/GetUnreadCount",
			procedure: "/chronos.notification.v1.NotificationService/GetUnreadCount",
			message:   fmt.Sprintf(`{"orgId":%q}`, syntheticOrgID),
			call: func(ctx context.Context, c *http.Client, bearer string, opts ...connectrpc.ClientOption) (string, error) {
				res, err := notificationv1connect.NewNotificationServiceClient(c, h.baseURL, opts...).
					GetUnreadCount(ctx, authed(&notificationv1.GetUnreadCountRequest{
						OrgId: syntheticOrgID,
					}, bearer))
				if err != nil {
					return "", err
				}
				return fingerprintUnread(res.Msg), nil
			},
		},
		{
			name:      "NotificationService/GetNotificationPreferences",
			procedure: "/chronos.notification.v1.NotificationService/GetNotificationPreferences",
			message:   fmt.Sprintf(`{"orgId":%q}`, syntheticOrgID),
			call: func(ctx context.Context, c *http.Client, bearer string, opts ...connectrpc.ClientOption) (string, error) {
				res, err := notificationv1connect.NewNotificationServiceClient(c, h.baseURL, opts...).
					GetNotificationPreferences(ctx, authed(
						&notificationv1.GetNotificationPreferencesRequest{OrgId: syntheticOrgID}, bearer))
				if err != nil {
					return "", err
				}
				return fingerprintPreferences(res.Msg), nil
			},
		},
		{
			name:      "ProfileService/GetProfile",
			procedure: "/chronos.profile.v1.ProfileService/GetProfile",
			message:   `{}`,
			call: func(ctx context.Context, c *http.Client, bearer string, opts ...connectrpc.ClientOption) (string, error) {
				res, err := profilev1connect.NewProfileServiceClient(c, h.baseURL, opts...).
					GetProfile(ctx, authed(&profilev1.GetProfileRequest{}, bearer))
				if err != nil {
					return "", err
				}
				return fingerprintProfile(res.Msg), nil
			},
		},
	}
}

// ---------------------------------------------------------------------------
// fingerprints
// ---------------------------------------------------------------------------
//
// Each reduces a reply to the fields that must not vary with the wire format.
// Timestamps that move on every authenticated request — a session's lastSeenAt,
// its rolling idle deadline, the process uptime — are deliberately excluded: a
// difference there is the clock, not the protocol, and including it would make
// the matrix flake instead of assert.

func fingerprintStatus(m *systemv1.GetStatusResponse) string {
	names := make([]string, 0, len(m.GetDependencies()))
	for _, d := range m.GetDependencies() {
		names = append(names, d.GetName())
	}
	sort.Strings(names)
	return fmt.Sprintf("ready=%t version=%q timezone=%q dependencies=%v",
		m.GetReady(), m.GetVersion(), m.GetTimezone(), names)
}

func fingerprintUser(m *identityv1.GetUserResponse) string {
	return fmt.Sprintf("subject=%s user=%s state=%s verified=%t",
		m.GetSubjectId(), m.GetUserId(), m.GetState(), m.GetEmailVerified())
}

func fingerprintSessions(m *identityv1.ListSessionsResponse) string {
	ids := make([]string, 0, len(m.GetSessions()))
	for _, s := range m.GetSessions() {
		ids = append(ids, fmt.Sprintf("%s@%s", s.GetSessionId(), s.GetAssuranceLevel()))
	}
	sort.Strings(ids)
	return fmt.Sprintf("sessions=%v next=%q", ids, m.GetNextPageToken())
}

func fingerprintMethods(m *identityv1.ListMethodsResponse) string {
	kinds := make([]string, 0, len(m.GetMethods()))
	for _, k := range m.GetMethods() {
		kinds = append(kinds, fmt.Sprintf("%s/usable=%t", k.GetKind(), k.GetUsable()))
	}
	sort.Strings(kinds)
	return fmt.Sprintf("methods=%v", kinds)
}

func fingerprintLoginHistory(m *identityv1.ListLoginHistoryResponse) string {
	outcomes := make([]string, 0, len(m.GetAttempts()))
	for _, a := range m.GetAttempts() {
		outcomes = append(outcomes, fmt.Sprintf("%t/%s", a.GetSucceeded(), a.GetReason()))
	}
	return fmt.Sprintf("attempts=%v next=%q", outcomes, m.GetNextPageToken())
}

func fingerprintFeed(m *notificationv1.ListNotificationsResponse) string {
	ids := make([]string, 0, len(m.GetNotifications()))
	for _, n := range m.GetNotifications() {
		ids = append(ids, n.GetNotificationId())
	}
	sort.Strings(ids)
	return fmt.Sprintf("notifications=%v next=%q", ids, m.GetNextPageToken())
}

func fingerprintUnread(m *notificationv1.GetUnreadCountResponse) string {
	return fmt.Sprintf("unread=%d", m.GetUnread())
}

func fingerprintPreferences(m *notificationv1.GetNotificationPreferencesResponse) string {
	channels := make([]string, 0, len(m.GetChannels()))
	for _, c := range m.GetChannels() {
		channels = append(channels, fmt.Sprintf("%s=%t", c.GetChannel(), c.GetEnabled()))
	}
	sort.Strings(channels)
	governed := make([]string, 0, len(m.GetGovernedClasses()))
	for _, c := range m.GetGovernedClasses() {
		governed = append(governed, c.String())
	}
	sort.Strings(governed)
	return fmt.Sprintf("channels=%v governed=%v", channels, governed)
}

func fingerprintProfile(m *profilev1.GetProfileResponse) string {
	return fmt.Sprintf("subject=%s name=%q locale=%q timezone=%q",
		m.GetSubjectId(), m.GetDisplayName(), m.GetLocale(), m.GetTimezone())
}

// ---------------------------------------------------------------------------
// reading an error off the wire
// ---------------------------------------------------------------------------

// reasonOf extracts the machine-readable reason a client is supposed to branch
// on (CONVENTIONS §5.1).
//
// It returns the reason and whether a chronos.errors.v1.ErrorDetail was present
// at all, because those are different findings: a wrong reason is a mapping bug,
// and a MISSING detail is the contract not reaching the client — which is what
// would happen if a protocol dropped the detail on the way.
func reasonOf(err error) (string, bool) {
	var ce *connectrpc.Error
	if !errors.As(err, &ce) {
		return "", false
	}
	for _, d := range ce.Details() {
		msg, derr := d.Value()
		if derr != nil {
			continue
		}
		if detail, ok := msg.(*errorsv1.ErrorDetail); ok {
			return detail.GetReason(), true
		}
	}
	return "", false
}

// describe renders an error the way a failure message should: the code, the
// reason, and the message, so a diff between two protocols is readable without
// re-running anything.
func describe(err error) string {
	if err == nil {
		return "<nil>"
	}
	reason, ok := reasonOf(err)
	if !ok {
		reason = "<no chronos.errors.v1.ErrorDetail>"
	}
	return fmt.Sprintf("code=%s reason=%s message=%q",
		connectrpc.CodeOf(err), reason, strings.TrimSpace(err.Error()))
}

// ---------------------------------------------------------------------------
// mutating cases
// ---------------------------------------------------------------------------

// mutationCase is one authenticated mutating RPC, described well enough to send
// it over any transport and over raw HTTP.
type mutationCase struct {
	name      string
	procedure string
	message   string
	call      func(ctx context.Context, c *http.Client, bearer, key string, opts ...connectrpc.ClientOption) error
}

// mutations is the repeatable half of the authenticated write surface.
//
// Every case here is chosen to be REPEATABLE, because the matrix runs each once
// per transport: a case that changed the world on every call would make the
// sixth run assert something the first did not. Both push cases are repeatable
// by design and say so in the schema — re-registering the same browser "is the
// NORMAL case, not an error", and removing an endpoint that was never registered
// "is not an error" — and neither loads an aggregate.
//
// The two mutations that DO load an aggregate, ProfileService/UpdateProfile and
// NotificationService/SetNotificationPreferences, are deliberately absent: they
// succeed exactly once per subject against this server and then fail INTERNAL
// forever. That is not a property of any protocol, so it does not belong in a
// protocol matrix — it is a composition-root defect, and
// TestASecondWriteToAnAggregateIsRefused states it once, with the reproduction.
func mutations() []mutationCase {
	return []mutationCase{
		{
			name:      "NotificationService/RegisterPushSubscription",
			procedure: "/chronos.notification.v1.NotificationService/RegisterPushSubscription",
			message: fmt.Sprintf(`{"orgId":%q,"endpoint":"https://push.example.test/matrix",`+
				`"p256dh":%q,"auth":%q}`, syntheticOrgID, pushP256DH, pushAuth),
			call: func(ctx context.Context, c *http.Client, bearer, key string, opts ...connectrpc.ClientOption) error {
				req := connectrpc.NewRequest(&notificationv1.RegisterPushSubscriptionRequest{
					OrgId:    syntheticOrgID,
					Endpoint: "https://push.example.test/matrix",
					P256Dh:   pushP256DH,
					Auth:     pushAuth,
				})
				stamp(req.Header(), bearer, key)
				_, err := notificationv1connect.NewNotificationServiceClient(c, h.baseURL, opts...).
					RegisterPushSubscription(ctx, req)
				return err
			},
		},
		{
			name:      "NotificationService/RemovePushSubscription",
			procedure: "/chronos.notification.v1.NotificationService/RemovePushSubscription",
			message: fmt.Sprintf(`{"orgId":%q,"endpoint":"https://push.example.test/never-registered"}`,
				syntheticOrgID),
			call: func(ctx context.Context, c *http.Client, bearer, key string, opts ...connectrpc.ClientOption) error {
				req := connectrpc.NewRequest(&notificationv1.RemovePushSubscriptionRequest{
					OrgId:    syntheticOrgID,
					Endpoint: "https://push.example.test/never-registered",
				})
				stamp(req.Header(), bearer, key)
				_, err := notificationv1connect.NewNotificationServiceClient(c, h.baseURL, opts...).
					RemovePushSubscription(ctx, req)
				return err
			},
		},
	}
}

// pushP256DH and pushAuth are a well-formed Web Push keypair's public halves.
// They are shapes, not secrets: the schema constrains them to base64url and
// nothing in this build decrypts anything with them.
const (
	pushP256DH = "BEl62iUYgUivxIkv69yViEuiBIa-Ib9-SkvMeAtA3LFgDzkrxZJjSgSnfckjBJuBkr3qBUYIHBQFLXYp5Nksh8U"
	pushAuth   = "tBHItJI5svbpez7KI4CCXg"
)

// stamp sets the two headers every authenticated mutation needs.
func stamp(header http.Header, bearer, key string) {
	if bearer != "" {
		header.Set(interceptor.AuthorizationHeader, "Bearer "+bearer)
	}
	if key != "" {
		header.Set(interceptor.IdempotencyHeader, key)
	}
}
