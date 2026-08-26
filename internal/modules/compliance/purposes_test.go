package compliance_test

import (
	"testing"

	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// These hold together the one CROSS-PACKAGE copy Article 21 requires.
//
// `internal/platform/notify` restates the two purpose strings, because the
// kernel may not import a module (depguard: platform-is-pure) and the vocabulary
// belongs to compliance's domain. Protobuf has the same problem with identifier
// patterns and `identity_token.purpose`'s CHECK constraint has it with
// `app.TokenPurpose`: the boundary cannot reference the constant, so a test
// holds the two together instead.
//
// They live in the MODULE package rather than in `domain`, because a domain test
// importing the notification kernel would make the aggregate's own test suite
// depend on a delivery mechanism — and `domain` is the one layer this
// repository keeps free of everything.

// TestEveryObjectionablePurposeIsADomainPurpose.
//
// The failure it catches is total and silent. A purpose string that differed by
// one character on either side would make every objection to it record
// correctly, project correctly, and match nothing at send time: the row is in
// the table, the person is told the processing stopped, and the mail keeps
// arriving.
//
// It runs in BOTH directions on purpose. A class whose purpose is not in the
// domain set means the dispatcher asks a question no objection can ever answer;
// a domain purpose no class rests on means the endpoint offers to stop
// processing that nothing consults — a right implemented as a promise, which is
// worse than one that is honestly absent.
func TestEveryObjectionablePurposeIsADomainPurpose(t *testing.T) {
	fromClasses := map[string]notify.Class{}
	for _, c := range []notify.Class{
		notify.Security, notify.Transactional, notify.Activity,
		notify.Product, notify.Operator,
	} {
		if purpose, ok := c.ObjectionablePurpose(); ok {
			fromClasses[purpose] = c
		}
	}
	if len(fromClasses) == 0 {
		t.Fatal("no notification class rests on an objectionable purpose, so Article 21 " +
			"stops nothing and this test would pass against a deleted feature")
	}

	inDomain := map[string]bool{}
	for _, p := range domain.Purposes() {
		inDomain[string(p)] = true
	}

	for purpose, class := range fromClasses {
		if !inDomain[purpose] {
			t.Errorf("notify.Class %v rests on purpose %q, which this module cannot "+
				"record. Every objection to it would match nothing at send time: the row "+
				"is written, the person is told processing stopped, and the mail keeps "+
				"arriving", class, purpose)
		}
	}
	for purpose := range inDomain {
		if _, enforced := fromClasses[purpose]; !enforced {
			t.Errorf("purpose %q can be objected to and no notification class rests on "+
				"it, so the objection stops nothing", purpose)
		}
	}
}

// TestSecurityAndTransactionalCannotBeObjectedTo.
//
// Article 21 reaches processing grounded in legitimate interests. Security
// alerts and transactional mail rest on contract and on the controller's own
// legal obligations, so the right does not reach them — and a control a session
// holder could set to stop a password-changed alert is the tripwire disabled by
// the takeover itself.
//
// Asserted from THIS module because this is where the purposes are declared: if
// one were ever added for a contract-based class, it would be added here.
func TestSecurityAndTransactionalCannotBeObjectedTo(t *testing.T) {
	for _, c := range []notify.Class{notify.Security, notify.Transactional, notify.Operator} {
		if purpose, ok := c.ObjectionablePurpose(); ok {
			t.Errorf("class %v is objectionable under purpose %q. Article 21 does not "+
				"reach processing grounded in contract or in a legal obligation, and a "+
				"control that stops a security alert is the one an attacker sets first",
				c, purpose)
		}
	}
}
