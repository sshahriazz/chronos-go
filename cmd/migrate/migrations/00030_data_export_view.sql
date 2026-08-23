-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- data_export_view — one row per Article 15 / Article 20 request
-- ---------------------------------------------------------------------------
-- What the subject polls, and what a controller reads when asked "did we answer
-- that request". Derived entirely from the compliance log and rebuildable from
-- position zero.
--
-- # No org_id, and no row security
--
-- A data-subject request is a fact about a PERSON, not about their membership of
-- any tenant: somebody in three organizations exercises Article 15 once and gets
-- one bundle. Scoping this by organization would make the answer depend on which
-- tenant they happened to be looking at, and would let one organization's
-- administrator see that a person had asked — which is nobody's business but the
-- subject's and the controller's. The same argument
-- processing_restriction_view makes, for the same reason.
--
-- # No personal data, which is what makes this projectable at all
--
-- subject_id is a pseudonym (ADR-002) and manifest_key is an opaque object key
-- carrying no business meaning (CLAUDE.md). The bundle's CONTENTS live in the
-- object store under the subject's own prefix, where erasure already deletes
-- them — so erasing somebody removes their exports without this table needing a
-- column blanked.
CREATE TABLE data_export_view (
    export_id  text PRIMARY KEY,
    subject_id text NOT NULL,

    -- pending → ready, or pending → failed. Never ready → failed: a late
    -- failure from an earlier attempt must not overwrite a fetchable bundle,
    -- which the aggregate refuses and this constraint records the shape of.
    status text NOT NULL,

    -- Set on completion only. The object the subject downloads.
    manifest_key text,

    -- How many stored files the manifest references. Reported so "ready" and
    -- "ready and it found none of your files" are different answers.
    object_count integer NOT NULL DEFAULT 0,

    -- Set on failure only, and it is the coarse machine string the event
    -- carries — never an underlying error, which would name a bucket, a key and
    -- an endpoint in a table that outlives the incident.
    failure_reason text,

    requested_at timestamptz NOT NULL,
    settled_at   timestamptz,

    CONSTRAINT data_export_status CHECK (
        status IN ('pending', 'ready', 'failed')
    ),

    -- A ready export MUST name its manifest, and a failed one MUST state why.
    -- Either violated produces a row the poll endpoint cannot answer from:
    -- "ready" with nowhere to fetch, or "failed" with nothing to tell the
    -- person. The aggregate refuses both; this is the second, independent guard.
    CONSTRAINT data_export_ready_has_manifest CHECK (
        status <> 'ready' OR manifest_key IS NOT NULL
    ),
    CONSTRAINT data_export_failed_has_reason CHECK (
        status <> 'failed' OR failure_reason IS NOT NULL
    ),
    CONSTRAINT data_export_object_count CHECK (object_count >= 0)
);

COMMENT ON TABLE data_export_view IS
    'One row per data-subject export request. Polled by the subject; evidence that Article 15 was answered.';

-- "What has this person asked for", newest first. The subject's own list, and
-- the only query this table serves besides the primary-key lookup.
CREATE INDEX data_export_subject_idx
    ON data_export_view (subject_id, requested_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON data_export_view TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS data_export_view;
-- +goose StatementEnd
