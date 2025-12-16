package analyzer

import (
	"context"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/free5gc/anlf/internal/analyzer/queue"
	"github.com/free5gc/anlf/pkg/models"
)

const floatTolerance = 1e-9

type MockExportHandler struct {
	enqueueCount atomic.Int32
}

func (m *MockExportHandler) Handle(msg *queue.ExportMessage) error {
	m.enqueueCount.Add(1)
	return nil
}

type MockAnomalyDetector struct {
	enabled bool
}

func (m *MockAnomalyDetector) EnqueueBatch(batch *models.BatchUeTrafficRecords) error {
	return nil
}

func (m *MockAnomalyDetector) IsEnabled() bool {
	return m.enabled
}

func TestFlowAnalyzer_GlobalStats_ActiveUsersOnly(t *testing.T) {
	mockHandler := &MockExportHandler{}
	exportQueue := queue.NewExportQueue(queue.QueueConfig{
		BufferSize:  100,
		WorkerCount: 2,
	}, mockHandler)

	detector := &MockAnomalyDetector{enabled: false}
	featureChan := make(chan *models.BatchUeTrafficRecords, 10)
	analyzer := NewFlowAnalyzer(featureChan, exportQueue, detector)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := analyzer.Start(ctx); err != nil {
		t.Fatalf("Failed to start analyzer: %v", err)
	}

	// Create batch with mixed active and inactive UEs
	batch := &models.BatchUeTrafficRecords{
		Records: []*models.UeTrafficRecord{
			// Active UE 1
			{
				UeIp: "60.60.0.1",
				Supi: "imsi-001010000000001",
				UeFeatureVector: models.UeFeatureVector{
					LogPPS:      4.0,
					AvgLen:      800.0,
					NewFlowRate: 0.2,
				},
			},
			// Active UE 2
			{
				UeIp: "60.60.0.2",
				Supi: "imsi-001010000000002",
				UeFeatureVector: models.UeFeatureVector{
					LogPPS:      2.0,
					AvgLen:      400.0,
					NewFlowRate: 0.1,
				},
			},
			// Inactive UE (all zeros)
			{
				UeIp: "60.60.0.3",
				Supi: "imsi-001010000000003",
				UeFeatureVector: models.UeFeatureVector{
					LogPPS:      0.0,
					AvgLen:      0.0,
					NewFlowRate: 0.0,
				},
			},
			// Inactive UE (all zeros)
			{
				UeIp: "60.60.0.4",
				Supi: "imsi-001010000000004",
				UeFeatureVector: models.UeFeatureVector{
					LogPPS:      0.0,
					AvgLen:      0.0,
					NewFlowRate: 0.0,
				},
			},
		},
		BatchSize: 4,
	}

	featureChan <- batch
	time.Sleep(100 * time.Millisecond)

	// Verify that global stats are calculated from only 2 active UEs
	if batch.GlobalStats == nil {
		t.Fatal("Expected GlobalStats to be set")
	}

	expectedAvgPPS := (4.0 + 2.0) / 2.0     // Should be 3.0 (only active UEs)
	expectedAvgFlow := (0.2 + 0.1) / 2.0    // Should be 0.15
	expectedAvgLen := (800.0 + 400.0) / 2.0 // Should be 600.0

	if math.Abs(batch.GlobalStats.AvgLogPPS-expectedAvgPPS) > floatTolerance {
		t.Errorf("Expected AvgLogPPS %.2f (from 2 active UEs), got %.2f", expectedAvgPPS, batch.GlobalStats.AvgLogPPS)
	}

	if math.Abs(batch.GlobalStats.AvgFlowRate-expectedAvgFlow) > floatTolerance {
		t.Errorf("Expected AvgFlowRate %.2f (from 2 active UEs), got %.2f", expectedAvgFlow, batch.GlobalStats.AvgFlowRate)
	}

	if math.Abs(batch.GlobalStats.AvgLen-expectedAvgLen) > floatTolerance {
		t.Errorf("Expected AvgLen %.0f (from 2 active UEs), got %.0f", expectedAvgLen, batch.GlobalStats.AvgLen)
	}

	t.Log("✓ Global stats correctly calculated from only active UEs")

	if err := analyzer.Stop(2 * time.Second); err != nil {
		t.Fatalf("Failed to stop analyzer: %v", err)
	}
}

func TestFlowAnalyzer_GlobalStats_NoActiveUsers(t *testing.T) {
	mockHandler := &MockExportHandler{}
	exportQueue := queue.NewExportQueue(queue.QueueConfig{
		BufferSize:  100,
		WorkerCount: 2,
	}, mockHandler)

	detector := &MockAnomalyDetector{enabled: false}
	featureChan := make(chan *models.BatchUeTrafficRecords, 10)
	analyzer := NewFlowAnalyzer(featureChan, exportQueue, detector)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := analyzer.Start(ctx); err != nil {
		t.Fatalf("Failed to start analyzer: %v", err)
	}

	// Create batch with all inactive UEs
	batch := &models.BatchUeTrafficRecords{
		Records: []*models.UeTrafficRecord{
			{
				UeIp: "60.60.0.1",
				Supi: "imsi-001010000000001",
				UeFeatureVector: models.UeFeatureVector{
					LogPPS:      0.0,
					AvgLen:      0.0,
					NewFlowRate: 0.0,
				},
			},
			{
				UeIp: "60.60.0.2",
				Supi: "imsi-001010000000002",
				UeFeatureVector: models.UeFeatureVector{
					LogPPS:      0.0,
					AvgLen:      0.0,
					NewFlowRate: 0.0,
				},
			},
		},
		BatchSize: 2,
	}

	featureChan <- batch
	time.Sleep(100 * time.Millisecond)

	// When no active UEs, GlobalStats should be nil
	if batch.GlobalStats != nil {
		t.Errorf("Expected GlobalStats to be nil when no active UEs, got %+v", batch.GlobalStats)
	}

	t.Log("✓ GlobalStats correctly remains nil when no active UEs")

	if err := analyzer.Stop(2 * time.Second); err != nil {
		t.Fatalf("Failed to stop analyzer: %v", err)
	}
}

func TestFlowAnalyzer_GlobalStats_AllActiveUsers(t *testing.T) {
	mockHandler := &MockExportHandler{}
	exportQueue := queue.NewExportQueue(queue.QueueConfig{
		BufferSize:  100,
		WorkerCount: 2,
	}, mockHandler)

	detector := &MockAnomalyDetector{enabled: false}
	featureChan := make(chan *models.BatchUeTrafficRecords, 10)
	analyzer := NewFlowAnalyzer(featureChan, exportQueue, detector)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := analyzer.Start(ctx); err != nil {
		t.Fatalf("Failed to start analyzer: %v", err)
	}

	// Create batch with all active UEs
	batch := &models.BatchUeTrafficRecords{
		Records: []*models.UeTrafficRecord{
			{
				UeIp: "60.60.0.1",
				Supi: "imsi-001010000000001",
				UeFeatureVector: models.UeFeatureVector{
					LogPPS:      3.0,
					AvgLen:      500.0,
					NewFlowRate: 0.15,
				},
			},
			{
				UeIp: "60.60.0.2",
				Supi: "imsi-001010000000002",
				UeFeatureVector: models.UeFeatureVector{
					LogPPS:      5.0,
					AvgLen:      700.0,
					NewFlowRate: 0.25,
				},
			},
		},
		BatchSize: 2,
	}

	featureChan <- batch
	time.Sleep(100 * time.Millisecond)

	// Verify that global stats are calculated correctly from all UEs
	if batch.GlobalStats == nil {
		t.Fatal("Expected GlobalStats to be set")
	}

	expectedAvgPPS := (3.0 + 5.0) / 2.0     // Should be 4.0
	expectedAvgFlow := (0.15 + 0.25) / 2.0  // Should be 0.2
	expectedAvgLen := (500.0 + 700.0) / 2.0 // Should be 600.0

	if math.Abs(batch.GlobalStats.AvgLogPPS-expectedAvgPPS) > floatTolerance {
		t.Errorf("Expected AvgLogPPS %.2f, got %.2f", expectedAvgPPS, batch.GlobalStats.AvgLogPPS)
	}

	if math.Abs(batch.GlobalStats.AvgFlowRate-expectedAvgFlow) > floatTolerance {
		t.Errorf("Expected AvgFlowRate %.2f, got %.2f", expectedAvgFlow, batch.GlobalStats.AvgFlowRate)
	}

	if math.Abs(batch.GlobalStats.AvgLen-expectedAvgLen) > floatTolerance {
		t.Errorf("Expected AvgLen %.0f, got %.0f", expectedAvgLen, batch.GlobalStats.AvgLen)
	}

	t.Log("✓ Global stats correctly calculated from all active UEs")

	if err := analyzer.Stop(2 * time.Second); err != nil {
		t.Fatalf("Failed to stop analyzer: %v", err)
	}
}
