package notify_test

import (
	"context"
	"errors"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// ---------------------------------------------------------------------------
// the containment failure this exists to catch
// ---------------------------------------------------------------------------

// A resolver reading the wrong org — or joining one column wrong — returns
// another customer's administrators. Without a check, each of them is then told
// about a tenant they have nothing to do with.
func TestRecipientFromAnotherOrgIsRefused(t *testing.T) {
	cat := notify.NewCatalogue()
	notify.On[passwordChanged](cat, notify.Spec{
		Template: "identity.password_changed",
		Class:    notify.Security,
		Audience: notify.AudienceOrgAdmins,
	}, nil)

	leaky := resolverFunc(func(context.Context, notify.Audience, eventsourcing.Envelope) ([]notify.Recipient, error) {
		return []notify.Recipient{
			{SubjectID: "sub_ours", OrgID: "org_A"},
			{SubjectID: "sub_theirs", OrgID: "org_B"}, // a different customer
		}, nil
	})

	email := &spyTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Vault: vault{}, Transports: []notify.Transport{email}, Log: quiet(),
	})
	r := notify.NewEventReactor("notifications", cat, catCodec{},
		notify.NewRegistry().Register(notify.AudienceOrgAdmins, leaky), d)

	err := r.React(context.Background(), orgEnvelope("org_A"))
	if !errors.Is(err, notify.ErrCrossTenant) {
		t.Fatalf("a recipient from another organization must be refused, got %v", err)
	}
	if email.calls != 0 {
		t.Fatal("delivered to a recipient from another organization")
	}
	// Parked, not retried: the resolver will return the same people next time.
	if !errors.Is(err, eventsourcing.ErrPoison) {
		t.Error("a containment failure must be parked so it is seen, not retried into silence")
	}
}

// An org has exactly one owner, and that is not changeable (workspace.md §2).
// Zero means the read model is wrong; two means it is worse.
func TestOrgOwnerMustResolveToExactlyOne(t *testing.T) {
	for name, recipients := range map[string][]notify.Recipient{
		"nobody": {},
		"two": {
			{SubjectID: "sub_1", OrgID: "org_A"},
			{SubjectID: "sub_2", OrgID: "org_A"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := reactWithOwner(t, recipients)
			if !errors.Is(err, notify.ErrAudienceUnsupported) {
				t.Fatalf("an org resolving to %s owners must fail, got %v", name, err)
			}
		})
	}

	if err := reactWithOwner(t, []notify.Recipient{{SubjectID: "sub_1", OrgID: "org_A"}}); err != nil {
		t.Fatalf("exactly one owner is the correct case: %v", err)
	}
}

// Operator alerts must never be addressed to a tenant. A subject id here means
// operational detail about one customer is going to another.
func TestOperatorRecipientCannotCarryATenantSubject(t *testing.T) {
	cat := notify.NewCatalogue()
	notify.On[projectionStopped](cat, notify.Spec{
		Template: "operator.alert",
		Class:    notify.Operator,
		Audience: notify.AudienceOperator,
	}, nil)

	wrong := resolverFunc(func(context.Context, notify.Audience, eventsourcing.Envelope) ([]notify.Recipient, error) {
		return []notify.Recipient{{SubjectID: "sub_customer", Address: "someone@tenant.test"}}, nil
	})

	email := &spyTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Vault: vault{}, Transports: []notify.Transport{email}, Log: quiet(),
	})
	r := notify.NewEventReactor("notifications", cat, catCodec{},
		notify.NewRegistry().Register(notify.AudienceOperator, wrong), d)

	err := r.React(context.Background(), envelope("system.ProjectionStopped.v1", ""))
	if err == nil {
		t.Fatal("an operator alert addressed to a tenant subject must be refused")
	}
	if email.calls != 0 {
		t.Fatal("sent operational detail to a tenant address")
	}
}

// Contact details come from the vault at delivery time. An address arriving
// from a resolver came from somewhere else — an event payload, a read model
// column — and personal data must not travel that way (ADR-002).
func TestTenantRecipientCannotArriveWithAnAddress(t *testing.T) {
	err := reactWithOwner(t, []notify.Recipient{
		{SubjectID: "sub_1", OrgID: "org_A", Address: "leaked@example.test"},
	})
	if !errors.Is(err, notify.ErrAudienceUnsupported) {
		t.Fatalf("a resolver-supplied address must be refused, got %v", err)
	}
}

// Someone who is both the owner and an admin must not be told twice.
func TestDuplicateRecipientIsRefused(t *testing.T) {
	cat := notify.NewCatalogue()
	notify.On[passwordChanged](cat, notify.Spec{
		Template: "identity.password_changed",
		Class:    notify.Security,
		Audience: notify.AudienceOrgAdmins,
	}, nil)

	dup := resolverFunc(func(context.Context, notify.Audience, eventsourcing.Envelope) ([]notify.Recipient, error) {
		return []notify.Recipient{
			{SubjectID: "sub_1", OrgID: "org_A"},
			{SubjectID: "sub_1", OrgID: "org_A"},
		}, nil
	})

	d := notify.NewDispatcher(notify.Deps{Vault: vault{}, Log: quiet()})
	r := notify.NewEventReactor("notifications", cat, catCodec{},
		notify.NewRegistry().Register(notify.AudienceOrgAdmins, dup), d)

	if err := r.React(context.Background(), orgEnvelope("org_A")); err == nil {
		t.Fatal("one person resolved twice would be notified twice about one event")
	}
}

// ---------------------------------------------------------------------------
// registry composition
// ---------------------------------------------------------------------------

// An audience nothing answers must stay unanswerable — loudly — rather than be
// approximated. Notifying the wrong person is worse than notifying nobody.
func TestUnwiredAudienceIsRefusedNotGuessed(t *testing.T) {
	cat := notify.NewCatalogue()
	notify.On[passwordChanged](cat, notify.Spec{
		Template: "identity.password_changed",
		Class:    notify.Security,
		Audience: notify.AudienceOrgAdmins,
	}, nil)

	d := notify.NewDispatcher(notify.Deps{Vault: vault{}, Log: quiet()})
	// Only the subject audience is wired; org admins are not.
	reg := notify.NewRegistry().Register(notify.AudienceSubject, notify.SubjectAudiences{})
	r := notify.NewEventReactor("notifications", cat, catCodec{}, reg, d)

	err := r.React(context.Background(), orgEnvelope("org_A"))
	if !errors.Is(err, notify.ErrAudienceUnsupported) {
		t.Fatalf("an audience with no resolver must be refused, got %v", err)
	}
	if !errors.Is(err, eventsourcing.ErrPoison) {
		t.Error("it must park so the gap is visible rather than silently notifying nobody")
	}
}

func TestRegisteringAnAudienceTwicePanics(t *testing.T) {
	reg := notify.NewRegistry().Register(notify.AudienceSubject, notify.SubjectAudiences{})
	defer func() {
		if recover() == nil {
			t.Fatal("two answers to 'who is the org owner' must not be possible")
		}
	}()
	reg.Register(notify.AudienceSubject, notify.SubjectAudiences{})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func reactWithOwner(t *testing.T, recipients []notify.Recipient) error {
	t.Helper()
	cat := notify.NewCatalogue()
	notify.On[passwordChanged](cat, notify.Spec{
		Template: "identity.password_changed",
		Class:    notify.Security,
		Audience: notify.AudienceOrgOwner,
	}, nil)

	res := resolverFunc(func(context.Context, notify.Audience, eventsourcing.Envelope) ([]notify.Recipient, error) {
		return recipients, nil
	})
	d := notify.NewDispatcher(notify.Deps{
		Vault: vault{}, Transports: []notify.Transport{&spyTransport{ch: notify.ChannelEmail}}, Log: quiet(),
	})
	r := notify.NewEventReactor("notifications", cat, catCodec{},
		notify.NewRegistry().Register(notify.AudienceOrgOwner, res), d)

	return r.React(context.Background(), orgEnvelope("org_A"))
}

func orgEnvelope(orgID string) eventsourcing.Envelope {
	env := envelope("identity.PasswordChanged.v1", "sub_1")
	env.Meta.OrgID = orgID
	return env
}

type resolverFunc func(context.Context, notify.Audience, eventsourcing.Envelope) ([]notify.Recipient, error)

func (f resolverFunc) Resolve(
	ctx context.Context, a notify.Audience, env eventsourcing.Envelope,
) ([]notify.Recipient, error) {
	return f(ctx, a, env)
}
