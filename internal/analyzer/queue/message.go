package queue

import "github.com/free5gc/anlf/pkg/models"

// MessageType represents the type of export message
type MessageType string

const (
	// MessageTypeTrafficRecord for UE traffic data export
	MessageTypeTrafficRecord MessageType = "traffic_record"
	// MessageTypeInferenceResult for LLM inference results export
	MessageTypeInferenceResult MessageType = "inference_result"
)

// ExportMessage is a generic message wrapper for different export types
type ExportMessage struct {
	Type MessageType
	Data interface{}
}

// NewTrafficRecordMessage creates an export message for traffic record
func NewTrafficRecordMessage(record *models.UeTrafficRecord) *ExportMessage {
	return &ExportMessage{
		Type: MessageTypeTrafficRecord,
		Data: record,
	}
}

// AsTrafficRecord safely converts message data to UeTrafficRecord
func (m *ExportMessage) AsTrafficRecord() (*models.UeTrafficRecord, bool) {
	rec, ok := m.Data.(*models.UeTrafficRecord)
	return rec, ok
}

// NewInferenceResultMessage creates an export message for inference result
func NewInferenceResultMessage(result *models.InferenceResult) *ExportMessage {
	return &ExportMessage{
		Type: MessageTypeInferenceResult,
		Data: result,
	}
}

// AsInferenceResult safely converts message data to InferenceResult
func (m *ExportMessage) AsInferenceResult() (*models.InferenceResult, bool) {
	result, ok := m.Data.(*models.InferenceResult)
	return result, ok
}
