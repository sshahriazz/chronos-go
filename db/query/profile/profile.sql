-- Queries for the profile projection.
--
-- Read-only from the application's side. The single write here is the
-- projector's upsert: nothing else may touch this table, because it is derived
-- from `profile.ProfileUpdated.v1` and must stay reconstructable from position
-- zero (ADR-019).

-- name: UpsertProfile :exec
-- The sparse update, expressed in SQL.
--
-- THIS STATEMENT IS WHERE "absent means unchanged" LIVES. Every parameter that
-- can be omitted is passed as a nullable value: SQL NULL means the event did
-- not mention that field, and the COALESCE keeps whatever is already stored.
-- Anything else — including the empty string and zero — is a value the event
-- DID carry, so it wins.
--
-- That is the whole difference between "unchanged" and "cleared", and it is one
-- COALESCE per column. Removing one does not fail: it makes every update that
-- left a field out silently erase it, which is exactly the shape of bug the
-- pointer-per-field payload exists to prevent.
--
-- The DO UPDATE clause references the PARAMETERS rather than EXCLUDED, and that
-- is not a style choice. EXCLUDED holds the row the INSERT would have written,
-- where the COALESCEs above have already turned every absent field into a
-- default — so `avatar_object_key = EXCLUDED.avatar_object_key` would clear the
-- avatar on every update that did not mention it.
--
-- Upsert, not insert: a projector is replayed on restart and on rebuild, so the
-- same event WILL arrive twice and an insert would fail the second time and
-- stall the projection permanently.
--
-- LAST WRITER WINS, and the ordering is the STREAM's rather than the clock's.
-- All of one person's profile changes live on one stream, so by the time two
-- concurrent saves reach here they are already totally ordered.
INSERT INTO profile_view (
    subject_id,
    display_name_set, locale_set, timezone_set,
    avatar_object_key, avatar_content_type, avatar_size_bytes,
    updated_at
) VALUES (
    $1,
    COALESCE($2::boolean, false),
    COALESCE($3::boolean, false),
    COALESCE($4::boolean, false),
    COALESCE($5::text, ''),
    COALESCE($6::text, ''),
    COALESCE($7::bigint, 0),
    $8
)
ON CONFLICT (subject_id) DO UPDATE SET
    display_name_set    = COALESCE($2::boolean, profile_view.display_name_set),
    locale_set          = COALESCE($3::boolean, profile_view.locale_set),
    timezone_set        = COALESCE($4::boolean, profile_view.timezone_set),
    avatar_object_key   = COALESCE($5::text,    profile_view.avatar_object_key),
    avatar_content_type = COALESCE($6::text,    profile_view.avatar_content_type),
    avatar_size_bytes   = COALESCE($7::bigint,  profile_view.avatar_size_bytes),
    updated_at          = $8;

-- name: GetProfileView :one
-- One person's own configured profile. Filtered by pseudonym, which the caller
-- cannot name: it comes from the authenticated session.
SELECT subject_id,
       display_name_set, locale_set, timezone_set,
       avatar_object_key, avatar_content_type, avatar_size_bytes,
       updated_at
FROM profile_view
WHERE subject_id = $1;

-- name: TruncateProfiles :exec
-- TRUNCATE, not DELETE: `Projection.Reset` is one TRUNCATE for every projection
-- in this system, and a rebuild runs in an unscoped system transaction (ADR-019).
TRUNCATE TABLE profile_view;
