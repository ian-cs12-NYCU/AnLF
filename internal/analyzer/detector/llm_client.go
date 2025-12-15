package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/free5gc/anlf/internal/logger"
	"github.com/free5gc/anlf/pkg/models"
)

type LLMClient struct {
	serverURL    string
	httpClient   *http.Client
	timeout      time.Duration
	systemPrompt string // Cached system prompt content
}

type LLMClientConfig struct {
	ServerURL        string
	Timeout          time.Duration
	SystemPromptPath string // Path to system prompt file
}

func NewLLMClient(cfg LLMClientConfig) *LLMClient {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}

	// Load system prompt from file if path is provided
	var systemPrompt string
	if cfg.SystemPromptPath != "" {
		if content, err := os.ReadFile(cfg.SystemPromptPath); err != nil {
			logger.AnalyzerLog.Warnf("Failed to read system prompt file %s: %v, using empty prompt", cfg.SystemPromptPath, err)
			systemPrompt = ""
		} else {
			systemPrompt = string(content)
			logger.AnalyzerLog.Infof("Loaded system prompt from %s (%d bytes)", cfg.SystemPromptPath, len(content))
		}
	}

	return &LLMClient{
		serverURL: cfg.ServerURL,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		timeout:      cfg.Timeout,
		systemPrompt: systemPrompt,
	}
}

func (c *LLMClient) Predict(ctx context.Context, record *models.UeTrafficRecord) (*models.InferenceResult, error) {
	req := &models.InferenceRequest{
		SystemPrompt: c.systemPrompt,
		Record:       record,
		Timestamp:    time.Now().Unix(),
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

	logger.AnalyzerLog.Debugf("[LLMClient] Sending inference request to %s for UE %s", c.serverURL, record.UeIp)
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		logger.AnalyzerLog.Warnf("[LLMClient] Failed to connect to LLM server at %s: %v", c.serverURL, err)
		return nil, fmt.Errorf("failed to send request to LLM server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.AnalyzerLog.Warnf("[LLMClient] LLM server returned error status %d for UE %s: %s", resp.StatusCode, record.UeIp, string(body))
		return nil, fmt.Errorf("LLM server returned status %d: %s", resp.StatusCode, string(body))
	}

	var result models.InferenceResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	logger.AnalyzerLog.Debugf("[LLMClient] Received inference result for UE %s: prediction=%s, score=%.2f, confidence=%.2f",
		record.UeIp, result.Prediction, result.AnomalyScore, result.Confidence)

	return &result, nil
}

func (c *LLMClient) HealthCheck(ctx context.Context) error {
	logger.AnalyzerLog.Infof("[LLMClient] Checking LLM server health at: %s", c.serverURL)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		logger.AnalyzerLog.Warnf("[LLMClient] ❌ LLM server is UNREACHABLE at %s", c.serverURL)
		return fmt.Errorf("LLM server unreachable at %s: %w", c.serverURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.AnalyzerLog.Warnf("[LLMClient] ❌ LLM server returned unhealthy status %d: %s", resp.StatusCode, string(body))
		return fmt.Errorf("LLM server unhealthy: status %d", resp.StatusCode)
	}

	logger.AnalyzerLog.Infof("[LLMClient] ✓ LLM server health check PASSED")
	return nil
}
