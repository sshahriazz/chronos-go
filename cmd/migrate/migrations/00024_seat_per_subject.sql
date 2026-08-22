-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- One seat per person per organization, enforced by the database
-- ---------------------------------------------------------------------------
-- workspace.md §2: "a seat is per person per ORGANIZATION, not per membership".
-- Until now that was true only because every caller remembered to ask "is this
-- person already in the organization" before reserving — and once invitations
-- existed there were two callers whose questions were blind to each other.
--
-- A pending invitation holds a seat and creates no membership row. So somebody
-- invited to workspace A and added directly to workspace B is counted as two
-- people: the invitation's conditional check sees no membership, the direct
-- add's conditional check sees no membership, and both reserve. The
-- organization is charged twice for one person, silently, in the direction they
-- notice last.
--
-- This makes the second reservation impossible rather than merely unlikely. The
-- conditional checks stay — they are what makes the common case cheap and what
-- reports `seat_consumed` honestly — but they are no longer the only thing
-- standing between the customer and a double charge.
--
-- # Why the predicate, and why it is a prefix
--
-- Only SEAT limits are per-person. `workspaces.count` records the CREATING
-- ADMIN as its subject_ref, so one admin opening three workspaces is three rows
-- with one subject_ref — a unique index without this predicate would cap every
-- organization at one workspace per admin.
--
-- The prefix matches domain.LimitKey.PerSubject, and a test asserts the two
-- agree. An index predicate cannot call Go, and duplicating the rule is the
-- price of having it enforced where it cannot be forgotten.
CREATE UNIQUE INDEX quota_reservation_one_seat_per_subject
    ON quota_reservation (org_id, limit_key, subject_ref)
    WHERE limit_key LIKE 'seats.%';

COMMENT ON INDEX quota_reservation_one_seat_per_subject IS
    'A person holds at most one seat per pool per organization (workspace.md §2).';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS quota_reservation_one_seat_per_subject;
-- +goose StatementEnd
