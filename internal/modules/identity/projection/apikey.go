package projection

import (
	"context"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// APIKeyName keys the checkpoint row and the single-writer lease.
//
// Permanent: renaming it silently restarts the projection from zero, which for
// this table means every key management screen goes blank until the replay
// catches up.
const APIKeyName = "identity_api_key"

// APIKey builds `api_key_view` and `service_account_view`.
//
// # Two tables, one projection, and why that is not a violation
//
// CONVENTIONS §8 says one projector owns one table, and the rule it is really
// making is that one table has ONE WRITER — two writers make rebuild order
// undefined. This owns both tables and is the only writer of either, so the
// property holds. They are together rather than split because a key names its
// owner and the screen renders the two joined: splitting them would give two
// checkpoints that can be at different positions, and a key would then be
// visible with an owner that does not exist yet.
//
// # What it deliberately does NOT write
//
// The digests. Those are `api_key_secret`, written by the command handler,
// because no digest is in the log and no replay could restore one (migration
// 00051). And `last_used_at`, which is a coalesced write by the authenticator:
// there is no `ApiKeyUsed` event and there must not be one, because an event per
// REQUEST makes the log grow with traffic rather than with state and the cost
// lands at rebuild time (identity.md §13).
//
// # What a rebuild costs, stated plainly
//
// This table can be rebuilt from position zero and doing so does NOT sign any
// key out — which is the deliberate difference from the session projection, and
// migration 00051's header gives the reason: the authenticator resolves a key
// from `api_key_secret` alone, because a rebuild that broke every integration in
// a customer's fleet is an outage with no human in the loop to recover from it.
// What a rebuild loses for its duration is the management SCREEN and
// `last_used_at`, which is a hint rather than a fact.
type APIKey struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*APIKey)(nil)

// NewAPIKey wires the four handlers.
func NewAPIKey(codec eventsourcing.Codec) *APIKey {
	d := projection.NewDispatch(codec)

	d.On[contract.ServiceAccountCreated](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.ServiceAccountCreated,
	) error {
		w.Exec(identitydb.UpsertServiceAccount,
			e.ServiceAccountID, e.OrgID, e.Name, e.CreatedBy, e.CreatedAt)
		return nil
	})

	d.On[contract.ApiKeyCreated](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.ApiKeyCreated,
	) error {
		// DO NOTHING on conflict, not DO UPDATE — see UpsertApiKey. A replay must
		// not resurrect a key that was revoked after it was created.
		w.Exec(identitydb.UpsertApiKey,
			e.KeyID, e.OrgID, string(e.OwnerKind), e.OwnerID, e.Scopes,
			e.ExpiresAt, e.CreatedBy, e.CreatedAt)
		return nil
	})

	d.On[contract.ApiKeyRotated](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.ApiKeyRotated,
	) error {
		// Only the deadline and the rotation stamp. The scopes, the owner and the
		// org binding are deliberately not in the statement: a rotation that
		// could change what a key may do would be an escalation wearing the name
		// of routine maintenance.
		//
		// PreviousRetiresAt is NOT projected. It is a fact about a SECRET, and
		// secrets are not in this table — `api_key_secret.retires_at` carries it,
		// written by the command handler in the same request. Projecting it here
		// would put a deadline on a screen that nothing enforces.
		w.Exec(identitydb.RotateApiKeyView, e.KeyID, e.ExpiresAt, e.RotatedAt)
		return nil
	})

	d.On[contract.ApiKeyRevoked](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.ApiKeyRevoked,
	) error {
		// The PROJECTION half of a revocation. The other half — deleting the
		// secret rows — happens in the command handler, in the same request, and
		// neither alone closes the window: this one waits for the projector, and
		// that one leaves nothing in the log saying why the key stopped working
		// (operator/app/operators.go, Disable).
		w.Exec(identitydb.RevokeApiKeyView, e.KeyID, e.RevokedAt)
		return nil
	})

	return &APIKey{dispatch: d}
}

func (k *APIKey) Name() string { return APIKeyName }

// Filter covers the two categories this projection reads, and nothing else.
//
// STREAM prefixes rather than the `identity.` event-type prefix the account and
// session projections use. Those two read events from the user stream and the
// session stream and from the authentication journal, so a type filter is the
// only one that covers them. This one reads exactly two categories, and naming
// them means the subscription skips every account, credential and session event
// in the log rather than decoding each one to discover it is not handled —
// which on a busy installation is the whole of the log (ADR-042).
func (k *APIKey) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{
			string(app.APIKeyCategory) + "-",
			string(app.ServiceAccountCategory) + "-",
		},
	}
}

func (k *APIKey) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return k.dispatch.Apply(ctx, w, env)
}

func (k *APIKey) Handles(eventType string) bool { return k.dispatch.Handles(eventType) }

// Reset empties both tables for a rebuild.
//
// Both, in one call, because they are one projection with one checkpoint —
// truncating one alone would leave the other at a position it no longer has rows
// for, and a key would come back before its owner did.
//
// TRUNCATE and not DELETE: a rebuild runs from an UNSCOPED system transaction,
// which under row-level security can see no rows and would therefore delete none
// — leaving a "rebuilt" projection full of its old contents. TRUNCATE is a
// table-level operation and is not filtered by row security (ADR-019).
func (k *APIKey) Reset(ctx context.Context, q db.Querier) error {
	if _, err := q.Exec(ctx, identitydb.TruncateApiKeys); err != nil {
		return err
	}
	_, err := q.Exec(ctx, identitydb.TruncateServiceAccounts)
	return err
}
