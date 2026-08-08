# API Error Catalogue

> **Generated** from `internal/platform/errs`. Do not edit.
> Run `make api-docs`.

Clients branch on `reason`, never on the HTTP status or the message.
The status and Connect code are shown for transport handling only.

| Reason | Connect code | HTTP | Retryable | Meaning | Client should |
| --- | --- | --- | --- | --- | --- |
| `UNAUTHENTICATED` | `unauthenticated` | 401 | **yes** | No session, or the access token is invalid or expired. | Refresh the token; if that fails, sign in again. |
| `STEP_UP_REQUIRED` | `permission_denied` | 403 | **yes** | The session is authenticated but below the assurance level this operation requires. | Prompt for step-up (MFA or passkey), then retry. |
| `ACCESS_DENIED` | `permission_denied` | 403 | no | Authenticated and visible, but this principal lacks the required relation. | Ask a workspace or organization admin for access. Do NOT offer an upgrade. |
| `PLAN_UPGRADE_REQUIRED` | `failed_precondition` | 412 | no | The capability is not included in the organization's current plan. | Offer an upgrade. Do NOT tell the user to ask an admin. |
| `QUOTA_EXCEEDED` | `failed_precondition` | 412 | no | A plan limit has been reached — seats, workspaces, or a metered dimension. | Show what is exhausted and offer to reduce usage or upgrade. |
| `ORG_SUSPENDED` | `failed_precondition` | 412 | no | The organization's subscription is suspended, so writes are blocked. | Direct the owner to billing. Reads, billing and export remain available. |
| `NOT_FOUND` | `not_found` | 404 | no | The resource does not exist, or the caller may not learn that it does. | Treat as absent. This response is deliberately indistinguishable from a cross-tenant denial. |
| `CONFLICT` | `aborted` | 409 | **yes** | Optimistic concurrency: the resource changed between read and write. | Re-read and retry. Expected under concurrency, not an error condition. |
| `VALIDATION_FAILED` | `invalid_argument` | 400 | no | The request failed schema or domain validation. | Fix the input; the metadata names the offending field. |
| `RATE_LIMITED` | `resource_exhausted` | 429 | **yes** | Too many requests. | Back off and retry with jitter. |
| `INTERNAL` | `internal` | 500 | **yes** | An unclassified server failure. Detail is deliberately withheld. | Retry with backoff; report the trace id if it persists. |

## The distinction that matters most

`ACCESS_DENIED` and `PLAN_UPGRADE_REQUIRED` are both refusals and must never
be collapsed into a generic 403. One means *ask an admin*; the other means
*upgrade your plan*. They lead to completely different user journeys, and a
client that cannot tell them apart will send people down the wrong one.

## Why NOT_FOUND is deliberately ambiguous

`NOT_FOUND` covers three cases: the resource does not exist, it exists but the
caller may not know that, and it exists but the caller is refused. This is
intentional (ADR-036) — distinguishing them across a tenant boundary would let
identifiers be probed for existence.

Inside a tenant, where the caller has already proven membership, errors *are*
specific.
