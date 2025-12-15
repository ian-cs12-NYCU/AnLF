package detector

import (
"bytes"
"context"
"encoding/json"
"fmt"
"io"
"net/http"
"time"

"github.com/free5gc/anlf/internal/logger"
"github.com/free5gc/anlf/pkg/models"
)

type LLMClient struct {
serverURL  string
httpClient *http.Client
timeout    time.Duration
}

type LLMClientConfig struct {
ServerURL string
Timeout   time.Duration
}

func NewLLMClient(cfg LLMClientConfig) *LLMClient {
if cfg.Timeout == 0 {
cfg.Timeout = 5 * time.Second
}

return &LLMClient{
serverURL: cfg.ServerURL,
httpClient: &http.Client{
Timeout: cfg.Timeout,
},
timeout: cfg.Timeout,
}
}

func (c *LLMClient) Predict(ctx context.Context, record *models.UeTrafficRecord) (*models.InferenceResult, error) {
req := &models.InferenceRequest{
Record:    record,
Timestamp: time.Now().Unix(),
}

jsonData, err := json.Marshal(req)
if err != nil {
return nil, fmt.Errorf("failed to marshal request: %w", err)
}

httpReq, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/predict", bytes.NewBuffer(jsonData))
if err != nil {
return nil, fmt.Errorf("failed to create request: %w", err)
}

httpReq.Header.Set("Content-Type", "application/json")

logger.AnalyzerLog.Debugf("Sending inference request to LLM server for UE %s", record.UeIp)
resp, err := c.httpClient.Do(httpReq)
if err != nil {
return nil, fmt.Errorf("failed to send request: %w", err)
}
defer resp.Body.Close()

if resp.StatusCode != http.StatusOK {
body, _ := io.ReadAll(resp.Body)
return nil, fmt.Errorf("LLM server returned status %d: %s", resp.StatusCode, string(body))
}

var result models.InferenceResult
if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
return nil, fmt.Errorf("failed to decode response: %w", err)
}

logger.AnalyzerLog.Debugf("Received inference result for UE %s: %s (confidence: %.2f)",
record.UeIp, result.Prediction, result.Confidence)

return &result, nil
}

func (c *LLMClient) HealthCheck(ctx context.Context) error {
httpReq, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/health", nil)
if err != nil {
return fmt.Errorf("failed to create health check request: %w", err)
}

resp, err := c.httpClient.Do(httpReq)
if err != nil {
return fmt.Errorf("LLM server unreachable: %w", err)
}
defer resp.Body.Close()

if resp.StatusCode != http.StatusOK {
return fmt.Errorf("LLM server unhealthy: status %d", resp.StatusCode)
}

return nil
}
