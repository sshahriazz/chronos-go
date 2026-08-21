package api_test

import (
	"testing"

	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	"github.com/chronos/chronos-go/internal/modules/organization/api"
	"github.com/chronos/chronos-go/internal/modules/organization/domain"
)

// Every operation class the PROTO declares maps to a domain class.
//
// # Why this is derived from the descriptor rather than from a written list
//
// Two enums describe one thing — `optionsv1.OperationClass` on the wire and
// `domain.OperationClass` in the domain — and the domain cannot import the
// proto, so the mapping is hand-written and can fall behind. The drift is
// silent in the worst direction: a class added to the proto and forgotten here
// falls through to ClassUnknown, which EVERY status refuses. Every RPC declaring
// the new class is then denied in every state, which looks like a permissions
// bug and is a missing line in a switch.
//
// So the cases come from the enum's own descriptor. Adding a value to the proto
// fails this test until the mapping learns it, which is the only version of this
// check that cannot itself fall behind.
func TestEveryDeclaredOperationClassMaps(t *testing.T) {
	t.Parallel()

	values := optionsv1.OperationClass(0).Descriptor().Values()
	seen := map[domain.OperationClass]bool{}

	for i := 0; i < values.Len(); i++ {
		value := values.Get(i)
		class := optionsv1.OperationClass(value.Number())

		t.Run(string(value.Name()), func(t *testing.T) {
			got := api.OperationClassOf(class)

			if value.Number() == 0 {
				// UNSPECIFIED must map to the class every status refuses.
				if got != domain.ClassUnknown {
					t.Errorf("UNSPECIFIED maps to %q; an RPC that declared no class would "+
						"then be enforced as though it had declared one", got)
				}
				return
			}
			if got == domain.ClassUnknown {
				t.Fatalf("%s is declared in the proto and maps to nothing. Every RPC "+
					"declaring it is refused in EVERY subscription state, which reads as a "+
					"permissions bug and is a missing case in OperationClassOf",
					value.Name())
			}
			if seen[got] {
				t.Errorf("%s maps to %q, which another class already maps to; two wire "+
					"classes collapsing into one domain class makes them impossible to "+
					"gate differently", value.Name(), got)
			}
			seen[got] = true
		})
	}

	// The mapping is onto as well as total: every domain class is reachable from
	// the wire. An unreachable one is a rule in the §5.2 table that no RPC can
	// ever trigger.
	for _, class := range domain.OperationClasses() {
		if class == domain.ClassUnknown {
			continue
		}
		if !seen[class] {
			t.Errorf("no wire class maps to %q, so the row it occupies in the payment "+
				"matrix can never be reached", class)
		}
	}
}
