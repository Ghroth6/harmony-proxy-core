package policy

import "github.com/metacubex/mihomo/mobile/validation"

type ResourceVersion struct {
	RefID         string `json:"refId"`
	SourceDigest  string `json:"sourceDigest"`
	ContentDigest string `json:"contentDigest"`
	ByteLength    int64  `json:"byteLength"`
	RelativePath  string `json:"relativePath"`
}
type ResourceEvent struct {
	Sequence          string `json:"sequence"`
	TaskID            string `json:"taskId"`
	RefID             string `json:"refId"`
	Generation        uint64 `json:"generation"`
	NetworkGeneration uint64 `json:"networkGeneration"`
	Stage             string `json:"stage"`
	Code              string `json:"code"`
	ContentDigest     string `json:"contentDigest"`
	ByteLength        int64  `json:"byteLength"`
	RelativePath      string `json:"relativePath"`
}
type ResourcesReceipt struct {
	SchemaVersion         int                     `json:"schemaVersion"`
	OperationID           string                  `json:"operationId"`
	Generation            uint64                  `json:"generation"`
	Category              string                  `json:"category"`
	Code                  string                  `json:"code"`
	CandidateDigest       string                  `json:"candidateDigest"`
	InitialManifestDigest string                  `json:"initialManifestDigest"`
	ResourceAcquireCount  string                  `json:"resourceAcquireCount"`
	Adopted               []ResourceVersion       `json:"adopted"`
	Events                []ResourceEvent         `json:"events"`
	HistoryTruncated      bool                    `json:"historyTruncated"`
	CoreIdentity          validation.CoreIdentity `json:"coreIdentity"`
}

func (e *Engine) QueryResources(operationID string, generation uint64) ResourcesReceipt {
	receipt := ResourcesReceipt{SchemaVersion: 1, OperationID: operationID, Generation: generation, Category: "absent", Code: "", ResourceAcquireCount: e.ResourceAcquireCount(), Adopted: []ResourceVersion{}, Events: []ResourceEvent{}, CoreIdentity: validation.Identity()}
	if !safeOperation(operationID) || generation == 0 || generation > 2147483647 {
		receipt.Category = "failure"
		receipt.Code = "POLICY_REQUEST_BOUNDS"
		return receipt
	}
	e.mu.Lock()
	current := e.current
	e.mu.Unlock()
	if current != nil {
		return current.observe(receipt)
	}
	return receipt
}
