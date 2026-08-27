-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- Erasure reaches notification's read models
-- ---------------------------------------------------------------------------
-- Three of this module's tables survived an erasure, and two of them held data
-- that destroying the subject's key does not reach.
--
-- `push_subscription` keeps `endpoint`, `p256dh`, `auth` and `user_agent`. The
-- endpoint is a stable per-browser identifier issued by a third-party push
-- service — it is not a vault reference and it is not encrypted, so ADR-002's
-- "erasure is a key destruction" does nothing to it. `notification_feed` keeps
-- `template` and an unvalidated `data` jsonb, and that jsonb carries free text
-- the person typed: the device label in `identity.new_device`, for one.
-- `notification_preference` keeps a channel toggle under the same pseudonym.
--
-- The DELETEs belong in the PROJECTIONS, for the two reasons the identity
-- session projection already gives (db/query/identity/session.sql,
-- `RevokeSessionsOfSubject`): each of these tables has exactly one writer
-- (CONVENTIONS §8), and the removal must survive a REBUILD, which replaying
-- `identity.UserErased.v1` re-runs. This migration exists because the
-- projection cannot perform them under the policy as it stands.
--
-- # Why a policy change is needed at all
--
-- `UserErased` is appended with `Metadata{OccurredAt, SubjectIDs}` and nothing
-- else (identity/app/erasure.go) — an account is a fact about a person, not
-- about an organization, so the event names none. The projector scopes each
-- batch from that metadata (`projection.ScopeOf`), and `scopeStatement` sets no
-- `app.org_id` when the scope is empty. Under `tenant_isolation` the DELETE
-- then matches nothing:
--
--     DELETE 0                -- app.org_id unset
--     count(*) = 1            -- read back under the owning org
--
-- Measured against the running server before this migration was written. That
-- is the silent failure this repository keeps hitting — a handler that runs,
-- commits, advances the checkpoint and removes nothing.
--
-- # Why the exception is a named subject rather than "unscoped may delete"
--
-- The obvious widening is `USING (current_setting('app.org_id', true) IS NULL)`
-- for DELETE, and it would turn every forgotten tenant scope from "removes
-- nothing" into "removes every tenant's rows". This grants strictly less: a
-- statement may reach exactly the rows of the ONE subject it names in
-- `app.erased_subject_id`, and only while it names one. An unset or empty
-- setting is NULL after the NULLIF, `subject_id = NULL` is NULL, and a
-- permissive policy that is not true grants nothing — so this fails closed in
-- the same direction `authz.Decision` does.
--
-- No request path sets that setting. It is queued by the erasure handler of
-- each notification projection, immediately before its DELETE, as a
-- transaction-local `set_config(..., true)` in the same batch — which is the
-- same mechanism and the same lifetime as the tenant scope itself, so it
-- reverts with the implicit transaction and cannot be inherited by whoever
-- borrows the pooled connection next.
--
-- # Why SELECT as well as DELETE
--
-- A DELETE whose WHERE names a column has to READ the rows it will remove, and
-- PostgreSQL applies SELECT policies to that read. With only the DELETE policy
-- in place the probe above still reported `DELETE 0`; with both it reported
-- `DELETE 1` and the row was gone. Two narrow policies rather than one
-- `FOR ALL`, because `FOR ALL` with no `WITH CHECK` reuses its `USING`
-- expression as the check and would also permit INSERTING rows for that subject
-- into any organization. Nothing needs that, so nothing is granted it.

-- notification_feed --------------------------------------------------------

CREATE POLICY subject_erasure_read ON notification_feed
    AS PERMISSIVE FOR SELECT
    USING (subject_id = NULLIF(current_setting('app.erased_subject_id', true), ''));

CREATE POLICY subject_erasure_delete ON notification_feed
    AS PERMISSIVE FOR DELETE
    USING (subject_id = NULLIF(current_setting('app.erased_subject_id', true), ''));

-- push_subscription --------------------------------------------------------

CREATE POLICY subject_erasure_read ON push_subscription
    AS PERMISSIVE FOR SELECT
    USING (subject_id = NULLIF(current_setting('app.erased_subject_id', true), ''));

CREATE POLICY subject_erasure_delete ON push_subscription
    AS PERMISSIVE FOR DELETE
    USING (subject_id = NULLIF(current_setting('app.erased_subject_id', true), ''));

-- notification_preference --------------------------------------------------
--
-- Included, and the decision is worth recording rather than implying. A channel
-- toggle is not personal data the way an endpoint is: the row holds a channel
-- name, a boolean and a pseudonym whose key is gone, and nothing in it can be
-- read back to a person. It is deleted anyway because the row can never be
-- useful again — the pseudonym is not reissued, so no future account can own
-- it — and because "an erased subject has no rows in notification" is a
-- property that can be tested, while "an erased subject has no rows in two of
-- notification's three tables" is a sentence somebody has to maintain.

CREATE POLICY subject_erasure_read ON notification_preference
    AS PERMISSIVE FOR SELECT
    USING (subject_id = NULLIF(current_setting('app.erased_subject_id', true), ''));

CREATE POLICY subject_erasure_delete ON notification_preference
    AS PERMISSIVE FOR DELETE
    USING (subject_id = NULLIF(current_setting('app.erased_subject_id', true), ''));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP POLICY IF EXISTS subject_erasure_delete ON notification_preference;
DROP POLICY IF EXISTS subject_erasure_read   ON notification_preference;
DROP POLICY IF EXISTS subject_erasure_delete ON push_subscription;
DROP POLICY IF EXISTS subject_erasure_read   ON push_subscription;
DROP POLICY IF EXISTS subject_erasure_delete ON notification_feed;
DROP POLICY IF EXISTS subject_erasure_read   ON notification_feed;
-- +goose StatementEnd
