-- +goose Up
-- +goose StatementBegin

-- ===========================================================================
-- The customer directory names the organization's OWNER
-- ===========================================================================
--
-- # The gap this closes
--
-- `RevealPersonalData` takes a subject pseudonym, and nothing in the operator
-- plane produced one. The directory has no member list — deliberately, that is
-- operator.md §4's minimisation — so an operator looking at a customer had no
-- way to name anybody in it. The endpoint was reachable only by somebody who
-- already knew a pseudonym, which in practice meant querying Postgres by hand.
--
-- An access-control feature that is unusable is not a strict one; it is one
-- people work around. The workaround here was a direct database query, which
-- has no justification, no audit entry and no bound on how many subjects it
-- returns — strictly worse than the endpoint it replaced.
--
-- # Why the OWNER specifically, and nobody else
--
-- operator.md §2 draws the line in the exclusion itself: out of scope are
-- "member email addresses BEYOND THE ORG OWNER'S, and only where a task needs
-- it". The owner is the one person the spec admits, and the reason is
-- practical — they are who a billing question, a suspension or an ownership
-- dispute is actually about.
--
-- So this is one column, not a member list. Adding a second subject here would
-- be adding the list §2 excludes, and it would have to argue past this comment
-- to do it.
--
-- # It is a PSEUDONYM, which is the whole point
--
-- `owner_subject_id` resolves to nothing on its own. Turning it into an address
-- still requires RevealPersonalData: one subject, a mandatory justification, an
-- audit entry written before the read, and the vault's own key. The directory
-- becomes usable without becoming a place addresses live, which is the
-- distinction compliance.md §1 draws — "projections store SubjectID; the vault
-- resolves it at read time".
--
-- TestOperatorProjectionsHoldNoPersonalData passes with this column present,
-- and that is correct rather than a hole in the test: its forbidden list names
-- addresses, names, phones and content, none of which this is.

ALTER TABLE operator_customer_list
    ADD COLUMN owner_subject_id text;

COMMENT ON COLUMN operator_customer_list.owner_subject_id IS
    'The organization owner''s pseudonym — the one person operator.md §2 admits. Resolves to nothing without RevealPersonalData, which requires a justification and writes an audit entry first.';

-- "Which customers does this person own", for the case that starts from a
-- person rather than from an organization — a support ticket naming a subject,
-- or an erasure request that has to find what it touches.
CREATE INDEX operator_customer_owner_idx ON operator_customer_list (owner_subject_id)
    WHERE owner_subject_id IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS operator_customer_owner_idx;
ALTER TABLE operator_customer_list DROP COLUMN IF EXISTS owner_subject_id;
-- +goose StatementEnd
