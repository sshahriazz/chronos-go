// Package api adapts organization's use cases to the transport layer.
package api

import (
	"context"
	"fmt"

	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	"github.com/chronos/chronos-go/internal/modules/organization/app"
	"github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// SubscriptionGate adapts the use case to the pipeline's port.
//
// The mapping from the proto enum to the domain's own class lives HERE because
// the domain may not import generated wire types (ADR-007) and app/ may not
// import gen/proto either. This is the one layer allowed to know both, which is
// exactly what an adapter is for.
type SubscriptionGate struct {
	gate *app.SubscriptionGate
}

var _ interceptor.Subscriptions = (*SubscriptionGate)(nil)

func NewSubscriptionGate(gate *app.SubscriptionGate) (*SubscriptionGate, error) {
	if gate == nil {
		return nil, fmt.Errorf("organization: a subscription gate is required")
	}
	return &SubscriptionGate{gate: gate}, nil
}

// Permit maps the declared class and delegates.
func (s *SubscriptionGate) Permit(ctx context.Context, class optionsv1.OperationClass) error {
	return s.gate.Permit(ctx, OperationClassOf(class))
}

// OperationClassOf maps the wire enum onto the domain's vocabulary.
//
// UNSPECIFIED maps to ClassUnknown, which every status refuses. That is the
// correct direction: an RPC whose class was never declared must not be treated
// as a read and waved through — it is a declaration somebody forgot, and the
// gate that would have caught it is this one.
//
// Exported so a test can assert the mapping is total. Two enums describing one
// thing drift, and this drift is silent: a new class would map to UNSPECIFIED
// and be refused everywhere, which reads as a permissions bug rather than a
// missing line here.
func OperationClassOf(class optionsv1.OperationClass) domain.OperationClass {
	switch class {
	case optionsv1.OperationClass_OPERATION_CLASS_READ:
		return domain.ClassRead
	case optionsv1.OperationClass_OPERATION_CLASS_WRITE:
		return domain.ClassWrite
	case optionsv1.OperationClass_OPERATION_CLASS_GROW:
		return domain.ClassGrow
	case optionsv1.OperationClass_OPERATION_CLASS_BILLING_VIEW:
		return domain.ClassBillingView
	case optionsv1.OperationClass_OPERATION_CLASS_BILLING_MANAGE:
		return domain.ClassBillingManage
	case optionsv1.OperationClass_OPERATION_CLASS_EXPORT:
		return domain.ClassExport
	default:
		return domain.ClassUnknown
	}
}
