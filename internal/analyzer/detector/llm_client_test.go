package detector

import (
"context"
"encoding/json"
"net/http"
"net/http/httptest"
"testing"
"time"

"github.com/free5gc/anlf/pkg/models"
)

func TestLLMClient_Predict_Success(t *testing.T) {
server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
if r.URL.Path != "/predict" {
t.Errorf("Expected path /predict, got %s", r.URL.Path)
}
if r.Method != http.MethodPost {
t.Errorf("Expected POST method, got %s", r.Method)
}

var req models.InferenceRequest
if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
t.Fatalf("Failed to decode request: %v", err)
}

resp := models.InferenceResult{
UeIp:         req.Record.UeIp,
Supi:         req.Record.Supi,
Timestamp:    req.Record.Timestamp,
IsAnomaly:    true,
AnomalyScore: 0.85,
Prediction:   "attack",
Confidence:   0.92,
ModelVersion: "v1.0",
}

w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(resp)
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

result, err := client.Predict(context.Background(), record)
if err != nil {
t.Fatalf("Predict failed: %v", err)
}

if result.UeIp != record.UeIp {
t.Errorf("Expected UE IP %s, got %s", record.UeIp, result.UeIp)
}

if !result.IsAnomaly {
t.Error("Expected IsAnomaly to be true")
}

if result.AnomalyScore != 0.85 {
t.Errorf("Expected anomaly score 0.85, got %.2f", result.AnomalyScore)
}

if result.Prediction != "attack" {
t.Errorf("Expected prediction 'attack', got %s", result.Prediction)
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

_, err := client.Predict(context.Background(), record)
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

_, err := client.Predict(ctx, record)
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
