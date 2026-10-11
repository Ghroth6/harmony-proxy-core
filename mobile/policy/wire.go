package policy

import (
	"errors"

	"github.com/metacubex/mihomo/mobile/internal/jsonvalue"
	"github.com/metacubex/mihomo/mobile/policy/contract"
)

var ErrEnvelope = errors.New("POLICY_JSON_INVALID")

func (e *Engine) PlanJSON(operationID string, input, availableJSON []byte) (PlanReceipt, error) {
	var available []contract.Resource
	if len(availableJSON) > contract.MaxControlBytes {
		return PlanReceipt{}, ErrEnvelope
	}
	if err := jsonvalue.DecodeRequired(availableJSON, &available); err != nil {
		return PlanReceipt{}, ErrEnvelope
	}
	return e.Plan(operationID, input, available), nil
}

func (e *Engine) ValidateJSON(operationID string, input, contextJSON []byte) (PreparedReceipt, error) {
	var prepared contract.PreparedContext
	if len(contextJSON) > contract.MaxControlBytes {
		return PreparedReceipt{}, ErrEnvelope
	}
	if err := jsonvalue.DecodeRequired(contextJSON, &prepared); err != nil {
		return PreparedReceipt{}, ErrEnvelope
	}
	return e.Validate(operationID, input, prepared), nil
}
