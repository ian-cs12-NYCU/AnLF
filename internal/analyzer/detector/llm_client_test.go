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

func TestLLMClient_PredictSingleUE_Success(t *testing.T) {
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

		// Extract messages and verify key-value format
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

		// Verify template-based format: "User Data: PPS:x.x, ..."
		if !strings.Contains(content, "User Data: PPS:") {
			t.Errorf("Expected template-based format with 'User Data:', got: %s", content)
		}

		// Return risk score in expected format
		openAIResp := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"content": "Risk Score: 0.85",
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
			LogPPS:      3.5,
			AvgLen:      600,
			NewFlowRate: 0.1,
			FanOut:      5,
			TcpRatio:    0.9,
			SynRatio:    0.1,
			RstRatio:    0.01,
		},
	}

	result, err := client.PredictSingleUE(context.Background(), record, nil)
	if err != nil {
		t.Fatalf("PredictSingleUE failed: %v", err)
	}

	if result.AnomalyScore != 0.85 {
		t.Errorf("Expected anomaly score 0.85, got %.2f", result.AnomalyScore)
	}

	if result.Supi != record.Supi {
		t.Errorf("Expected SUPI %s, got %s", record.Supi, result.Supi)
	}
}

func TestLLMClient_PredictSingleUESingleUE_ServerError(t *testing.T) {
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
		UeFeatureVector: models.UeFeatureVector{
			LogPPS: 3.5,
			AvgLen: 600,
		},
	}

	_, err := client.PredictSingleUE(context.Background(), record, nil)
	if err == nil {
		t.Error("Expected error on server failure, got nil")
	}
}

func TestLLMClient_PredictSingleUESingleUE_Timeout(t *testing.T) {
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
		UeFeatureVector: models.UeFeatureVector{
			LogPPS: 3.5,
			AvgLen: 600,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := client.PredictSingleUE(ctx, record, nil)
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
