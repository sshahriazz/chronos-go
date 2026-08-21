package connect_test

import (
	"testing"

	"connectrpc.com/connect"

	"github.com/chronos/chronos-go/internal/platform/errs"
	srvconnect "github.com/chronos/chronos-go/internal/server/connect"
)

// The PUBLISHED error catalogue says what this package actually sends.
//
// # The defect this exists to prevent, which shipped
//
// There are two tables describing the same fact and nothing compared them:
// errs.Catalogue() in the kernel, which is generated into docs/api/errors.md and
// into the OpenAPI spec, and codeFor in this package, which decides what goes on
// the wire. They disagreed for four of the eleven reasons.
//
// CONFLICT was documented as `aborted` and sent as `already_exists`.
// PLAN_UPGRADE_REQUIRED, QUOTA_EXCEEDED and ORG_SUSPENDED were documented as
// `failed_precondition`/412 and sent as `permission_denied`/403,
// `resource_exhausted`/429 and `permission_denied`/403.
//
// errors.md carries the line "docs and behaviour cannot disagree", which was
// true of the mechanism that GENERATES it — the doc comes from the same
// Catalogue() the server imports — and false of the thing it describes, because
// the transport mapping lives somewhere else entirely. A client written against
// the published catalogue would branch on a code the server never sends.
//
// Found by internal/adapter/protocolit, which provoked each reason over real
// HTTP and compared the answer with the document.
//
// This test is the comparison that was missing. It runs in the transport package
// because that is where codeFor lives and where the two can be seen together.
func TestThePublishedCatalogueMatchesWhatTheTransportSends(t *testing.T) {
	t.Parallel()

	for _, doc := range errs.Catalogue() {
		t.Run(string(doc.Reason), func(t *testing.T) {
			t.Parallel()

			// Round-trip a real error of this reason through the real mapping,
			// rather than reading codeFor's source. What a client sees is the
			// error this package builds, so that is what is compared.
			wire := srvconnect.Error(errs.New(doc.Reason, "provoked for the catalogue test"))

			gotCode := connect.CodeOf(wire)
			if gotCode.String() != doc.ConnectCode {
				t.Errorf("the catalogue publishes connect code %q for %s, but the transport "+
					"sends %q. A client branching on the published contract handles a code "+
					"this server never emits.", doc.ConnectCode, doc.Reason, gotCode)
			}

			// The HTTP status is Connect's own mapping of the code, so asserting the
			// code is what pins it; connect-go exposes no public CodeToHTTP to
			// compare against, and re-implementing its table here would be a third
			// copy of the fact this test exists to stop duplicating.
		})
	}
}

// Every reason the kernel defines appears in the published catalogue.
//
// A reason with no catalogue row is a code a client can receive and cannot look
// up. The generator that writes docs/api/errors.md iterates Catalogue(), so an
// unlisted reason is invisible to it — the omission produces no error anywhere,
// just a gap in the contract.
func TestEveryReasonIsPublished(t *testing.T) {
	t.Parallel()

	published := map[errs.Reason]bool{}
	for _, doc := range errs.Catalogue() {
		published[doc.Reason] = true
	}

	// The full set the kernel declares. Written out rather than derived, because
	// Go cannot range over the values of a constant block — the same reason
	// notification's domain.Classes() is enumerated by hand and then checked.
	all := []errs.Reason{
		errs.Unauthenticated, errs.StepUpRequired, errs.AccessDenied,
		errs.PlanUpgradeRequired, errs.QuotaExceeded, errs.OrgSuspended,
		errs.NotFound, errs.Conflict, errs.ValidationFailed,
		errs.RateLimited, errs.Internal,
	}
	for _, r := range all {
		if !published[r] {
			t.Errorf("%s is a reason this system can return and the published catalogue "+
				"does not list it; a client receiving it cannot look it up", r)
		}
	}
	if len(errs.Catalogue()) != len(all) {
		t.Errorf("the catalogue has %d rows and the kernel declares %d reasons; one of the "+
			"two lists has grown without the other", len(errs.Catalogue()), len(all))
	}
}
