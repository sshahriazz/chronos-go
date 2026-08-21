package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/notification/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// A real Firefox endpoint, in shape. Nothing is ever sent to it.
const goodEndpoint = "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABm7Qk"

// ---------------------------------------------------------------------------
// The endpoint is a request-forgery surface, and this is what closes it
// ---------------------------------------------------------------------------

// The server POSTs to whatever this field holds. Every row below is a URL that
// would make it POST somewhere only the server can reach, or with an authority
// the host check would not see.
func TestParsePushEndpointRefusesAnythingTheServerShouldNotPost(t *testing.T) {
	t.Parallel()

	for name, raw := range map[string]string{
		"plaintext":            "http://updates.push.services.mozilla.com/wpush/v2/x",
		"no scheme":            "updates.push.services.mozilla.com/wpush/v2/x",
		"file":                 "file:///etc/passwd",
		"empty":                "",
		"cloud metadata by ip": "https://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"loopback by ip":       "https://127.0.0.1/wpush",
		"private range by ip":  "https://10.0.0.5/wpush",
		"ipv6 loopback":        "https://[::1]/wpush",
		"localhost":            "https://localhost/wpush",
		"localhost suffix":     "https://push.localhost/wpush",
		"mdns suffix":          "https://vault.local/wpush",
		"internal suffix":      "https://admin.internal/wpush",
		"home arpa suffix":     "https://router.home.arpa/wpush",
		"credentials in url":   "https://user:secret@updates.push.services.mozilla.com/wpush",
		"non-https port":       "https://updates.push.services.mozilla.com:8080/wpush",
		"no host":              "https:///wpush",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := domain.ParsePushEndpoint(raw)
			if !errors.Is(err, domain.ErrEndpointRefused) {
				t.Fatalf("ParsePushEndpoint(%q) = (%q, %v), want ErrEndpointRefused",
					raw, got.String(), err)
			}
			if !got.IsZero() {
				t.Errorf("a refused endpoint still produced a usable value %q", got.String())
			}
		})
	}
}

func TestParsePushEndpointRefusesAnOversizedURL(t *testing.T) {
	t.Parallel()

	raw := "https://updates.push.services.mozilla.com/wpush/v2/" + strings.Repeat("a", 2048)
	if _, err := domain.ParsePushEndpoint(raw); !errors.Is(err, domain.ErrEndpointRefused) {
		t.Fatalf("a %d-byte endpoint was accepted: %v", len(raw), err)
	}
}

func TestParsePushEndpointAcceptsRealPushServices(t *testing.T) {
	t.Parallel()

	for name, raw := range map[string]string{
		"mozilla":      goodEndpoint,
		"fcm":          "https://fcm.googleapis.com/fcm/send/dQw4w9WgXcQ:APA91bH",
		"windows":      "https://wns2-par02p.notify.windows.com/w/?token=Ag",
		"explicit 443": "https://fcm.googleapis.com:443/fcm/send/abc",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := domain.ParsePushEndpoint(raw); err != nil {
				t.Fatalf("ParsePushEndpoint(%q): %v", raw, err)
			}
		})
	}
}

// The HOST is lowercased and the PATH is not. A push service's path is an
// opaque, case-sensitive token, and "normalising" it would produce a URL that
// 404s — while leaving the host in whatever case the browser reported would make
// two spellings of one endpoint into two subscriptions pushing to one device
// twice.
func TestParsePushEndpointNormalisesTheHostAndNotThePath(t *testing.T) {
	t.Parallel()

	e, err := domain.ParsePushEndpoint("https://FCM.GoogleAPIs.com/fcm/send/AbCdEf")
	if err != nil {
		t.Fatalf("ParsePushEndpoint: %v", err)
	}
	if e.Host() != "fcm.googleapis.com" {
		t.Errorf("Host() = %q, want the lowercased host", e.Host())
	}
	if !strings.HasSuffix(e.String(), "/fcm/send/AbCdEf") {
		t.Errorf("the path was altered: %q", e.String())
	}
	if strings.Contains(e.String(), "FCM.GoogleAPIs") {
		t.Errorf("the host was not normalised: %q", e.String())
	}

	other, err := domain.ParsePushEndpoint("https://fcm.googleapis.com/fcm/send/AbCdEf")
	if err != nil {
		t.Fatalf("ParsePushEndpoint: %v", err)
	}
	if e.String() != other.String() {
		t.Errorf("two spellings of one endpoint normalised differently: %q vs %q",
			e.String(), other.String())
	}
}

// ---------------------------------------------------------------------------
// The subscription identifier IS ADR-043's uniqueness rule
// ---------------------------------------------------------------------------

// One browser, two organizations, two DIFFERENT subscriptions.
//
// This is the assertion that catches dropping org_id from the derivation. That
// mutation gives two organizations one subscription id, which is also the
// PRIMARY KEY of push_subscription — so the second organization's row would
// collide on a constraint the upsert does not name, the projector would stall,
// and that person would receive no web push there at all. ADR-043 is the record
// of exactly that failure, found the first time in an index rather than in an
// identifier.
func TestPushSubscriptionIDIsScopedToTheOrganization(t *testing.T) {
	t.Parallel()

	e := mustEndpoint(t, goodEndpoint)
	a := domain.PushSubscriptionID("org_01ARZ3NDEKTSV4RRFFQ69G5FAA", e)
	b := domain.PushSubscriptionID("org_01ARZ3NDEKTSV4RRFFQ69G5FBB", e)

	if a.String() == b.String() {
		t.Fatalf("one browser produced the same subscription id %q in two organizations; "+
			"that id is push_subscription's primary key, so the second organization's "+
			"row cannot exist and that person receives no push there (ADR-043)", a)
	}
}

// The same organization and the same endpoint always resolve to the same
// subscription, which is what makes re-registering collapse onto one row and
// unsubscribing work without a lookup.
func TestPushSubscriptionIDIsStableForOneOrganizationAndEndpoint(t *testing.T) {
	t.Parallel()

	e := mustEndpoint(t, goodEndpoint)
	first := domain.PushSubscriptionID("org_01ARZ3NDEKTSV4RRFFQ69G5FAA", e)
	second := domain.PushSubscriptionID("org_01ARZ3NDEKTSV4RRFFQ69G5FAA", e)
	if first.String() != second.String() {
		t.Fatalf("the same browser in the same organization produced %q then %q; "+
			"every re-subscribe would create a row and that device would be pushed "+
			"to once per permission prompt it ever answered", first, second)
	}
}

// The NUL separator is what stops one (org, endpoint) pair being re-spelled as
// another. Without it, org "a" + endpoint "bc" and org "ab" + endpoint "c"
// would hash alike.
func TestPushSubscriptionIDCannotBeRespelled(t *testing.T) {
	t.Parallel()

	// The endpoints differ only in where the boundary falls relative to the org.
	one := domain.PushSubscriptionID("org_a", mustEndpoint(t, "https://push.example.test/bc"))
	two := domain.PushSubscriptionID("org_ab", mustEndpoint(t, "https://push.example.test/c"))
	if one.String() == two.String() {
		t.Fatal("two different (organization, endpoint) pairs hashed to one subscription id")
	}
}

func TestPushSubscriptionIDIsAPrefixedIdentifierThatCanNameAStream(t *testing.T) {
	t.Parallel()

	id := domain.PushSubscriptionID("org_01ARZ3NDEKTSV4RRFFQ69G5FAA", mustEndpoint(t, goodEndpoint))

	if _, err := ids.Parse[ids.PushSubscription](id.String()); err != nil {
		t.Fatalf("the subscription id does not round-trip through ids.Parse: %v", err)
	}
	// KurrentDB derives a stream's CATEGORY from everything before the first
	// dash, so an identifier containing one would silently split the category.
	if strings.Contains(id.String(), "-") {
		t.Fatalf("the subscription id %q contains a dash and cannot name a stream", id)
	}
	stream, err := eventsourcing.NewStreamID(domain.Category, id.String())
	if err != nil {
		t.Fatalf("NewStreamID: %v", err)
	}
	if stream.Category() != domain.Category {
		t.Errorf("stream %q has category %q, want %q", stream, stream.Category(), domain.Category)
	}
}

// ---------------------------------------------------------------------------
// The preference stream key
// ---------------------------------------------------------------------------

func TestPreferenceStreamKeyIsScopedToBothOrganizationAndSubject(t *testing.T) {
	t.Parallel()

	base := domain.PreferenceStreamKey("org_a", "subj_a")
	for name, got := range map[string]string{
		"another organization": domain.PreferenceStreamKey("org_b", "subj_a"),
		"another subject":      domain.PreferenceStreamKey("org_a", "subj_b"),
		"the pair re-spelled":  domain.PreferenceStreamKey("org_", "asubj_a"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got == base {
				t.Fatalf("%s resolves to the same preference stream %q; two people's "+
					"or two organizations' toggles would share one consistency boundary",
					name, base)
			}
		})
	}

	if domain.PreferenceStreamKey("org_a", "subj_a") != base {
		t.Error("the key is not stable for one (organization, subject) pair")
	}
}

func TestPreferenceStreamKeyCanNameAStream(t *testing.T) {
	t.Parallel()

	key := domain.PreferenceStreamKey("org_a", "subj_a")
	if strings.Contains(key, "-") {
		t.Fatalf("the preference stream key %q contains a dash and would split the category", key)
	}
	stream, err := eventsourcing.NewStreamID(domain.Category, key)
	if err != nil {
		t.Fatalf("NewStreamID: %v", err)
	}
	// The projectors filter on this prefix; a key that produced a different
	// category would be a stream no projector ever reads.
	if !strings.HasPrefix(stream.String(), "notification-") {
		t.Errorf("stream %q is outside the prefix every notification projector filters on", stream)
	}
}

// The stream name is permanent and appears in the $streams index forever. It
// must not carry the pseudonym in the clear, which is what the digest buys.
func TestPreferenceStreamKeyDoesNotCarryTheSubject(t *testing.T) {
	t.Parallel()

	key := domain.PreferenceStreamKey("org_01ARZ3NDEKTSV4RRFFQ69G5FAA", "subj_01ARZ3NDEKTSV4RRFFQ69G5FBB")
	if strings.Contains(key, "subj_") || strings.Contains(key, "org_") {
		t.Fatalf("the preference stream key %q contains an identifier in the clear; a "+
			"stream name is never rewritten and has no ciphertext for erasure to "+
			"destroy (ADR-048)", key)
	}
}

func mustEndpoint(t *testing.T, raw string) domain.PushEndpoint {
	t.Helper()
	e, err := domain.ParsePushEndpoint(raw)
	if err != nil {
		t.Fatalf("ParsePushEndpoint(%q): %v", raw, err)
	}
	return e
}
