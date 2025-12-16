package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
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

// BuildPrompt constructs the final LLM request with system prompt + user content
// This function is exposed for testing and debugging purposes (e.g., prompt_preview tool)
func (c *LLMClient) BuildPrompt(records []*models.UeTrafficRecord) (systemContent string, userContent string, err error) {
	// System prompt (loaded from file)
	systemContent = c.systemPrompt

	// Build user prompt with UE traffic data
	var userPrompt strings.Builder
	userPrompt.WriteString("Analyze these network traffic records and classify each as 'normal' or 'attack'.\n")
	userPrompt.WriteString("Return a JSON object with 'results' array containing one result per UE.\n\n")

	recordsJSON, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal records: %w", err)
	}
	userPrompt.Write(recordsJSON)

	userContent = userPrompt.String()
	return systemContent, userContent, nil
}

// PredictBatch sends a batch of UE traffic records to LLM server for anomaly detection
// Uses OpenAI-compatible API (/v1/chat/completions)
func (c *LLMClient) PredictBatch(ctx context.Context, records []*models.UeTrafficRecord) (*models.BatchInferenceResult, error) {
	logger.AnalyzerLog.Infof("[LLMClient] Attempting batch prediction for %d UEs", len(records))

	// Start latency measurement
	startTime := time.Now()

	// Build prompt using the new function
	systemContent, userContent, err := c.BuildPrompt(records)
	if err != nil {
		return nil, fmt.Errorf("failed to build prompt: %w", err)
	}

	// OpenAI Chat Completions API format with json_schema
	openAIReq := map[string]interface{}{
		"model": "default",
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": systemContent,
			},
			{
				"role":    "user",
				"content": userContent,
			},
		},
		"temperature": 0.1,
		"max_tokens":  1000,
		"response_format": map[string]interface{}{
			"type": "json_object",
			"schema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"results": map[string]interface{}{
						"type": "array",
						"items": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"supi": map[string]string{
									"type": "string",
								},
								"anomaly_score": map[string]string{
									"type": "number",
								},
							},
							"required": []string{"supi", "anomaly_score"},
						},
					},
				},
				"required": []string{"results"},
			},
		},
	}

	jsonData, err := json.Marshal(openAIReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OpenAI request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenAI request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	logger.AnalyzerLog.Debugf("[LLMClient] → Trying OpenAI API: POST %s/v1/chat/completions", c.serverURL)
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		logger.AnalyzerLog.Warnf("[LLMClient] ✗ OpenAI API connection failed: %v", err)
		return nil, fmt.Errorf("failed to send OpenAI request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.AnalyzerLog.Warnf("[LLMClient] ✗ Failed to read response body: %v", err)
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		logger.AnalyzerLog.Warnf("[LLMClient] ✗ OpenAI API returned status %d: %s", resp.StatusCode, string(respBody))
		return nil, fmt.Errorf("OpenAI API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	logger.AnalyzerLog.Debugf("[LLMClient] Raw OpenAI response (first 1000 chars): %s", string(respBody[:min(len(respBody), 1000)]))

	// Parse OpenAI response
	var openAIResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(respBody, &openAIResp); err != nil {
		logger.AnalyzerLog.Warnf("[LLMClient] ✗ Failed to decode OpenAI JSON response: %v", err)
		logger.AnalyzerLog.Warnf("[LLMClient] Response body was: %s", string(respBody))
		return nil, fmt.Errorf("failed to decode OpenAI response: %w", err)
	}

	if len(openAIResp.Choices) == 0 {
		logger.AnalyzerLog.Warnf("[LLMClient] ✗ OpenAI response has no choices")
		return nil, fmt.Errorf("no choices in OpenAI response")
	}

	// Parse the content as our BatchInferenceResult
	content := openAIResp.Choices[0].Message.Content
	logger.AnalyzerLog.Debugf("[LLMClient] Raw LLM content (length=%d chars): %s", len(content), content)

	// Clean potential markdown formatting and extract JSON
	content = strings.TrimSpace(content)

	// Remove markdown code blocks (```json ... ``` or ``` ... ```)
	if strings.Contains(content, "```") {
		// Remove opening ```json or ```
		content = strings.TrimPrefix(content, "```json")
		content = strings.TrimPrefix(content, "```")
		// Remove closing ```
		content = strings.TrimSuffix(content, "```")
		content = strings.TrimSpace(content)
	}

	// Try to extract JSON object if wrapped in text
	if idx := strings.Index(content, "{"); idx >= 0 {
		content = content[idx:]
	}
	if idx := strings.LastIndex(content, "}"); idx >= 0 {
		content = content[:idx+1]
	}

	logger.AnalyzerLog.Debugf("[LLMClient] Cleaned JSON content (length=%d chars): %s", len(content), content)

	var result models.BatchInferenceResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		logger.AnalyzerLog.Warnf("[LLMClient] ✗ Failed to parse LLM response as BatchInferenceResult: %v", err)
		logger.AnalyzerLog.Warnf("[LLMClient] Content length: %d bytes", len(content))
		if len(content) > 0 {
			logger.AnalyzerLog.Warnf("[LLMClient] Content preview (first 500 chars): %s", content[:min(len(content), 500)])
		} else {
			logger.AnalyzerLog.Warnf("[LLMClient] Content is EMPTY!")
		}

		// If parsing fails, create default results for fail-open
		logger.AnalyzerLog.Warnf("[LLMClient] Using fail-open: returning default 'normal' results for %d UEs", len(records))
		return c.createDefaultBatchResult(records), nil
	}

	// Validate results
	if len(result.Results) == 0 {
		logger.AnalyzerLog.Warnf("[LLMClient] LLM returned empty results array")
		return c.createDefaultBatchResult(records), nil
	}

	// Check if parsed UE count matches input count
	if len(result.Results) != len(records) {
		logger.AnalyzerLog.Warnf("[LLMClient] ⚠ UE count mismatch: sent %d UEs, but parsed %d results from LLM", len(records), len(result.Results))
	}

	// Calculate latency
	latency := time.Since(startTime)
	logger.AnalyzerLog.Infof("[LLMClient] ✓ Successfully parsed %d UE results (output size: %d bytes, latency: %v)", len(result.Results), len(content), latency)
	return &result, nil
}

// createDefaultBatchResult creates default "normal" results for fail-open when parsing fails
func (c *LLMClient) createDefaultBatchResult(records []*models.UeTrafficRecord) *models.BatchInferenceResult {
	results := make([]*models.InferenceResult, len(records))
	for i, record := range records {
		results[i] = &models.InferenceResult{
			Supi:         record.Supi,
			AnomalyScore: 0.1, // Default low risk score for fail-open
		}
	}
	return &models.BatchInferenceResult{
		Results: results,
	}
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
