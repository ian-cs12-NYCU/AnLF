package detector

import (
	"strings"
	"testing"

	"github.com/free5gc/anlf/pkg/models"
)

// TestBuildSingleUEPrompt_AllGlobalStats verifies all 8 global statistics are included in prompt
func TestBuildSingleUEPrompt_AllGlobalStats(t *testing.T) {
	// Create LLM client with test prompt
	client := &LLMClient{
		systemPrompt: `Test Prompt
Global Avg PPS: {global_avg_pps}
Global Avg Flow: {global_avg_flow}
Global Avg UL Len: {global_avg_ul_len}
Global Avg Fan Out: {global_avg_fan_out}
Global Avg DL PPS: {global_avg_dl_pps}
Global Avg DL Len: {global_avg_dl_len}
Global Avg PPS Ratio: {global_avg_pps_ratio}
Global Avg Byte Ratio: {global_avg_byte_ratio}
User Data: PPS:{log_pps}`,
	}

	// Create test record
	record := &models.UeTrafficRecord{
		UeFeatureVector: models.UeFeatureVector{
			UlLogPPS: 4.5,
		},
	}

	// Create global stats with all 8 fields
	globalStats := &models.GlobalNetworkStats{
		AvgUlLogPPS:    3.2,
		AvgDlLogPPS:    2.8,
		AvgNewFlowRate: 0.35,
		AvgUlLen:       650.0,
		AvgDlLen:       800.0,
		AvgPPSRatio:    1.15,
		AvgByteRatio:   1.45,
		AvgFanOut:      0.25,
	}

	// Build prompt
	systemContent, _ := client.BuildSingleUEPrompt(record, globalStats)

	// Verify all 8 global stats are replaced with actual values (not N/A or placeholder)
	expectedReplacements := map[string]string{
		"{global_avg_pps}":        "3.20",
		"{global_avg_flow}":       "0.35",
		"{global_avg_ul_len}":     "650",
		"{global_avg_fan_out}":    "0.25",
		"{global_avg_dl_pps}":     "2.80",
		"{global_avg_dl_len}":     "800",
		"{global_avg_pps_ratio}":  "1.15",
		"{global_avg_byte_ratio}": "1.45",
	}

	for placeholder, expectedValue := range expectedReplacements {
		if strings.Contains(systemContent, placeholder) {
			t.Errorf("Placeholder %s was not replaced in system prompt", placeholder)
		}
		if !strings.Contains(systemContent, expectedValue) {
			t.Errorf("Expected value %s not found in system prompt", expectedValue)
		}
	}

	// Ensure no "N/A" appears when global stats are provided
	if strings.Contains(systemContent, "N/A") {
		t.Error("System prompt contains 'N/A' when global stats were provided")
	}
}

// TestBuildSingleUEPrompt_NoGlobalStats verifies N/A is used when global stats are nil
func TestBuildSingleUEPrompt_NoGlobalStats(t *testing.T) {
	client := &LLMClient{
		systemPrompt: `Test Prompt
Global Avg PPS: {global_avg_pps}
Global Avg Flow: {global_avg_flow}
User Data: PPS:{log_pps}`,
	}

	record := &models.UeTrafficRecord{
		UeFeatureVector: models.UeFeatureVector{
			UlLogPPS: 4.5,
		},
	}

	// Build prompt without global stats
	systemContent, _ := client.BuildSingleUEPrompt(record, nil)

	// Verify N/A is used for all global placeholders
	naCount := strings.Count(systemContent, "N/A")
	if naCount < 2 { // At least 2 N/A should appear
		t.Errorf("Expected multiple 'N/A' placeholders, found %d", naCount)
	}

	// Ensure no unreplaced placeholders remain
	if strings.Contains(systemContent, "{global_avg_pps}") {
		t.Error("Placeholder {global_avg_pps} was not replaced with N/A")
	}
}

// TestBuildSingleUEPrompt_GlobalStatsInRealPrompt tests with actual prompt file
func TestBuildSingleUEPrompt_GlobalStatsInRealPrompt(t *testing.T) {
	// Create client with default prompt path
	client := NewLLMClient(LLMClientConfig{
		SystemPromptPath: "../../../prompts/anomaly_detection_single_ue.txt",
		ServerURL:        "http://test",
	})

	record := &models.UeTrafficRecord{
		UeFeatureVector: models.UeFeatureVector{
			UlLogPPS:    5.0,
			AvgLen:      512.0,
			NewFlowRate: 0.9,
			FanOut:      0.78,
			DlLogPPS:    1.7,
			DlAvgLen:    64.0,
			PPSRatio:    0.05,
			ByteRatio:   0.006,
		},
	}

	globalStats := &models.GlobalNetworkStats{
		AvgUlLogPPS:    3.2,
		AvgDlLogPPS:    2.8,
		AvgNewFlowRate: 0.3,
		AvgUlLen:       650.0,
		AvgDlLen:       800.0,
		AvgPPSRatio:    1.2,
		AvgByteRatio:   1.5,
		AvgFanOut:      0.2,
	}

	systemContent, userContent := client.BuildSingleUEPrompt(record, globalStats)

	// Verify system prompt contains all 8 global stats with values
	requiredGlobalValues := []string{
		"3.20", // AvgUlLogPPS
		"2.80", // AvgDlLogPPS
		"0.30", // AvgNewFlowRate
		"650",  // AvgUlLen
		"800",  // AvgDlLen
		"1.20", // AvgPPSRatio
		"1.50", // AvgByteRatio
		"0.20", // AvgFanOut
	}

	for _, value := range requiredGlobalValues {
		if !strings.Contains(systemContent, value) {
			t.Errorf("Global value %s not found in system prompt", value)
		}
	}

	// Verify user prompt contains UE data
	if !strings.Contains(userContent, "PPS:5.0") {
		t.Error("User prompt missing UE data")
	}

	// Verify no unreplaced placeholders remain
	if strings.Contains(systemContent, "{global_") {
		t.Error("System prompt still contains unreplaced global placeholders")
	}

	t.Logf("System prompt length: %d chars", len(systemContent))
	t.Logf("User prompt length: %d chars", len(userContent))
}
