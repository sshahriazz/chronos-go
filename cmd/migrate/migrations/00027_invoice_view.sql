-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- invoice_view — a REFERENCE and a STATUS, never an amount we computed
-- ---------------------------------------------------------------------------
-- billing.md §6 states the rule for discounts and it generalises to this whole
-- table: we never compute a total. Stripe's invoice is the number. Every money
-- column here is a value Stripe SENT, stored so a screen can render a history
-- without a round trip — not so anything can add them up.
--
-- The corollary decides the column types below. `amount_due` is Stripe's minor
-- unit (cents, or the currency's equivalent), stored as bigint exactly as it
-- arrived. Converting to a decimal here would mean choosing a scale per
-- currency, which is arithmetic, which is the thing we are refusing to
-- reimplement. Anything rendering this divides by the currency's own exponent.
--
-- # What this table is NOT for
--
-- It is not the system of record for whether an organization has paid. That is
-- the SUBSCRIPTION's status, which drives `org_status_view` and gate 3. An
-- unpaid invoice here and an Active organization is a normal, momentary state —
-- Stripe's Smart Retries are running — and code that suspended a tenant by
-- reading this table would fight the dunning schedule it does not own.
CREATE TABLE invoice_view (
    -- Stripe's id, and the primary key. Ours would be a second identifier for
    -- an object we do not own, and every webhook names Stripe's.
    invoice_id text PRIMARY KEY,

    org_id text NOT NULL,

    -- Stripe's subscription, so an invoice can be traced to what produced it
    -- even after the organization's own row has moved on. Empty for a one-off
    -- invoice, which this build does not create but Stripe permits an operator
    -- to.
    stripe_subscription_id text NOT NULL DEFAULT '',

    -- The HUMAN-FACING number (`INV-0001`), which is not the id and is what a
    -- customer quotes to support. Empty until Stripe finalizes: a draft has no
    -- number, and inventing one would create a reference nobody else can match.
    number text NOT NULL DEFAULT '',

    -- draft, open, paid, uncollectible, void. Stripe's own vocabulary, not a
    -- mapping of ours: this column exists to be shown, and a translation layer
    -- would make our word and the word on Stripe's dashboard differ during
    -- exactly the conversation where they must not.
    status text NOT NULL,

    -- Minor units, as sent. See the header.
    amount_due  bigint NOT NULL,
    amount_paid bigint NOT NULL,

    -- ISO 4217, lower case, as Stripe sends it. billing.md §5 case 12 locks a
    -- customer's currency to their first invoice, so this is also where that
    -- fact becomes observable.
    currency text NOT NULL,

    -- The billing period the invoice covers. Stripe's, not computed.
    period_start timestamptz,
    period_end   timestamptz,

    -- Stripe's hosted invoice page and PDF. We render neither.
    --
    -- Nullable-by-empty rather than NULL, like every other optional text column
    -- here, so a reader never has to handle two kinds of absent. Empty means
    -- Stripe has not produced one, which is true of a draft.
    hosted_url text NOT NULL DEFAULT '',
    pdf_url    text NOT NULL DEFAULT '',

    -- When Stripe created it. The ordering a person reading their billing
    -- history expects, and stable under our own re-processing.
    created_at timestamptz NOT NULL,

    -- When WE last applied a webhook to this row. Not the same fact as
    -- created_at, and the one that answers "is our copy stale".
    updated_at timestamptz NOT NULL,

    CONSTRAINT invoice_view_status CHECK (
        status IN ('draft', 'open', 'paid', 'uncollectible', 'void')
    ),

    -- A negative total is not a Stripe invoice; it is a decode that went wrong.
    -- Cheaper to refuse at the boundary than to explain a negative line on a
    -- customer's billing page.
    CONSTRAINT invoice_view_amounts CHECK (amount_due >= 0 AND amount_paid >= 0)
);

COMMENT ON TABLE invoice_view IS
    'Invoice references and statuses from Stripe. Never a computed total; not the source of truth for whether an org has paid — the subscription status is.';

ALTER TABLE invoice_view ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoice_view FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON invoice_view
    USING (org_id = current_setting('app.org_id', true))
    WITH CHECK (org_id = current_setting('app.org_id', true));

-- The billing history screen: newest first, keyset-paged on (created_at,
-- invoice_id). The id breaks ties, because Stripe can create several invoices
-- in the same second and a cursor on the timestamp alone would skip or repeat.
CREATE INDEX invoice_view_org_idx
    ON invoice_view (org_id, created_at DESC, invoice_id DESC);

GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON invoice_view TO chronos_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS invoice_view;
-- +goose StatementEnd
