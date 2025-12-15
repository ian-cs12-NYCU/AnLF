package queue

import "github.com/free5gc/anlf/pkg/models"

// MessageType represents the type of export message
type MessageType string

const (
	// MessageTypeTrafficRecord for UE traffic data export
	MessageTypeTrafficRecord MessageType = "traffic_record"
	// MessageTypeLLMInference for LLM inference results export (future)
	MessageTypeLLMInference MessageType = "llm_inference"
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
