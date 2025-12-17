package queue

import "github.com/free5gc/anlf/pkg/models"

// MessageType represents the type of export message
type MessageType string

const (
	// MessageTypeTrafficRecord for single UE traffic data export (legacy)
	MessageTypeTrafficRecord MessageType = "traffic_record"
	// MessageTypeBatchTrafficRecords for batch UE traffic data export
	MessageTypeBatchTrafficRecords MessageType = "batch_traffic_records"
	// MessageTypeInferenceResult for LLM inference results export
	MessageTypeInferenceResult MessageType = "inference_result"
	// MessageTypeEnhancedInferenceResult for LLM + Risk Scorer results export
	MessageTypeEnhancedInferenceResult MessageType = "enhanced_inference_result"
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

// NewBatchTrafficRecordsMessage creates an export message for batch traffic records
func NewBatchTrafficRecordsMessage(batch *models.BatchUeTrafficRecords) *ExportMessage {
	return &ExportMessage{
		Type: MessageTypeBatchTrafficRecords,
		Data: batch,
	}
}

// AsBatchTrafficRecords safely converts message data to BatchUeTrafficRecords
func (m *ExportMessage) AsBatchTrafficRecords() (*models.BatchUeTrafficRecords, bool) {
	batch, ok := m.Data.(*models.BatchUeTrafficRecords)
	return batch, ok
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

// NewEnhancedInferenceResultMessage creates an export message for enhanced inference result
func NewEnhancedInferenceResultMessage(result *models.EnhancedInferenceResult) *ExportMessage {
	return &ExportMessage{
		Type: MessageTypeEnhancedInferenceResult,
		Data: result,
	}
}

// AsEnhancedInferenceResult safely converts message data to EnhancedInferenceResult
func (m *ExportMessage) AsEnhancedInferenceResult() (*models.EnhancedInferenceResult, bool) {
	result, ok := m.Data.(*models.EnhancedInferenceResult)
	return result, ok
}
