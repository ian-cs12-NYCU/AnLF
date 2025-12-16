package detector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/free5gc/anlf/pkg/models"
)

func TestLLMClient_Predict_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expect OpenAI API path
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("Expected path /v1/chat/completions, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request: %v", err)
		}

		// Extract messages and user content safely
		messages, ok := req["messages"].([]interface{})
		if !ok || len(messages) < 2 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		userMsg, ok := messages[len(messages)-1].(map[string]interface{})
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		content, ok := userMsg["content"].(string)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Parse UE records from content (it's a formatted prompt, so extract JSON part)
		// The content format is: "Analyze... Return...\n\n[JSON array]"
		// Find the JSON array in the content
		jsonStart := strings.Index(content, "[")
		jsonEnd := strings.LastIndex(content, "]")
		if jsonStart < 0 || jsonEnd < 0 || jsonStart >= jsonEnd {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		jsonStr := content[jsonStart : jsonEnd+1]
		var records []*models.UeTrafficRecord
		if err := json.Unmarshal([]byte(jsonStr), &records); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if len(records) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Generate results
		results := make([]*models.InferenceResult, len(records))
		for i, record := range records {
			results[i] = &models.InferenceResult{
				Supi:         record.Supi,
				AnomalyScore: 0.85,
			}
		}

		// Build OpenAI response
		responseContent := map[string]interface{}{
			"results": results,
		}
		contentBytes, _ := json.Marshal(responseContent)

		openAIResp := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"content": string(contentBytes),
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(openAIResp)
	}))
	defer server.Close()

	client := NewLLMClient(LLMClientConfig{
		ServerURL: server.URL,
		Timeout:   5 * time.Second,
	})

	record := &models.UeTrafficRecord{
		UeIp:      "60.60.0.1",
		Supi:      "imsi-001010000000001",
		Timestamp: 1234567890,
		UeFeatureVector: models.UeFeatureVector{
			LogPPS: 3.5,
		},
	}

	// Test PredictBatch instead of removed Predict method
	results, err := client.PredictBatch(context.Background(), []*models.UeTrafficRecord{record})
	if err != nil {
		t.Fatalf("PredictBatch failed: %v", err)
	}

	if len(results.Results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results.Results))
	}

	result := results.Results[0]
	if result.AnomalyScore != 0.85 {
		t.Errorf("Expected anomaly score 0.85, got %.3f", result.AnomalyScore)
	}

	if result.Supi != record.Supi {
		t.Errorf("Expected SUPI %s, got %s", record.Supi, result.Supi)
	}
}

func TestLLMClient_Predict_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	client := NewLLMClient(LLMClientConfig{
		ServerURL: server.URL,
		Timeout:   5 * time.Second,
	})

	record := &models.UeTrafficRecord{
		UeIp:      "60.60.0.1",
		Supi:      "imsi-001010000000001",
		Timestamp: 1234567890,
	}

	_, err := client.PredictBatch(context.Background(), []*models.UeTrafficRecord{record})
	if err == nil {
		t.Error("Expected error on server failure, got nil")
	}
}

func TestLLMClient_Predict_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewLLMClient(LLMClientConfig{
		ServerURL: server.URL,
		Timeout:   100 * time.Millisecond,
	})

	record := &models.UeTrafficRecord{
		UeIp:      "60.60.0.1",
		Supi:      "imsi-001010000000001",
		Timestamp: 1234567890,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := client.PredictBatch(ctx, []*models.UeTrafficRecord{record})
	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
}

func TestLLMClient_HealthCheck_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("Expected path /health, got %s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := NewLLMClient(LLMClientConfig{
		ServerURL: server.URL,
		Timeout:   5 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := client.HealthCheck(ctx); err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}
}

func TestLLMClient_HealthCheck_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewLLMClient(LLMClientConfig{
		ServerURL: server.URL,
		Timeout:   5 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := client.HealthCheck(ctx)
	if err == nil {
		t.Error("Expected error on health check failure, got nil")
	}
}

func TestLLMClient_Predict_CountMismatch(t *testing.T) {
	// Mock server that returns fewer results than sent
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Always return only 1 result regardless of input count
		result := &models.InferenceResult{
			Supi:         "imsi-208930000000001",
			AnomalyScore: 0.5,
		}

		responseContent := map[string]interface{}{
			"results": []*models.InferenceResult{result},
		}
		contentBytes, _ := json.Marshal(responseContent)

		openAIResp := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"content": string(contentBytes),
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(openAIResp)
	}))
	defer server.Close()

	client := NewLLMClient(LLMClientConfig{
		ServerURL: server.URL,
		Timeout:   5 * time.Second,
	})

	// Send 3 UEs but server will only return 1
	records := []*models.UeTrafficRecord{
		{Supi: "imsi-208930000000001"},
		{Supi: "imsi-208930000000002"},
		{Supi: "imsi-208930000000003"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := client.PredictBatch(ctx, records)

	// Should succeed but log warning
	if err != nil {
		t.Fatalf("PredictBatch failed: %v", err)
	}

	if result == nil || len(result.Results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(result.Results))
	}

	// The warning should be logged (check manually or with log capture)
	t.Log("Warning about count mismatch should appear in logs: sent 3 UEs, parsed 1")
}
