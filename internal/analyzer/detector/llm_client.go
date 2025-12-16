package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/free5gc/anlf/internal/logger"
	"github.com/free5gc/anlf/pkg/models"
)

type LLMClient struct {
	serverURL     string
	httpClient    *http.Client
	timeout       time.Duration
	systemPrompt  string // Cached system prompt content
	scoreRegex    *regexp.Regexp
	maxConcurrent int     // Max concurrent requests (for semaphore)
	temperature   float64 // LLM temperature parameter
	maxTokens     int     // Max response tokens
}

type LLMClientConfig struct {
	ServerURL        string
	Timeout          time.Duration
	SystemPromptPath string  // Path to system prompt file
	MaxConcurrent    int     // Max concurrent requests (default: 100)
	Temperature      float64 // LLM temperature (default: 0.1)
	MaxTokens        int     // Max response tokens (default: 50)
}

func NewLLMClient(cfg LLMClientConfig) *LLMClient {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}

	if cfg.MaxConcurrent == 0 {
		cfg.MaxConcurrent = 100
	}

	if cfg.Temperature == 0 {
		cfg.Temperature = 0.1 // Default: low randomness for consistent detection
	}

	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = 50 // Default: sufficient for "Risk Score: X.X"
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

	// Optimized HTTP Client with connection pooling for high concurrency
	// Reference: high_speed_HTTPclient.md
	return &LLMClient{
		serverURL: cfg.ServerURL,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				MaxIdleConns:        1000,              // Allow large number of idle connections
				MaxIdleConnsPerHost: cfg.MaxConcurrent, // Critical: Must >= concurrent target
				IdleConnTimeout:     90 * time.Second,
				DisableKeepAlives:   false, // Ensure Keep-Alive is enabled
			},
		},
		timeout:       cfg.Timeout,
		systemPrompt:  systemPrompt,
		scoreRegex:    regexp.MustCompile(`Risk Score:\s*(0\.\d+|1\.0|0|1)`),
		maxConcurrent: cfg.MaxConcurrent,
		temperature:   cfg.Temperature,
		maxTokens:     cfg.MaxTokens,
	}
}

// BuildSingleUEPrompt builds prompt for a single UE (key-value format)
func (c *LLMClient) BuildSingleUEPrompt(record *models.UeTrafficRecord) (systemContent string, userContent string) {
	systemContent = c.systemPrompt

	// Key-value format to save input tokens
	userContent = fmt.Sprintf("Input: ID:%s, PPS:%.1f, Len:%d, Flow:%.2f, Fan:%d, TCP:%.1f, SYN:%.1f, RST:%.1f",
		record.Supi,
		record.UeFeatureVector.LogPPS,
		int(record.UeFeatureVector.AvgLen),
		record.UeFeatureVector.NewFlowRate,
		int(record.UeFeatureVector.FanOut),
		record.UeFeatureVector.TcpRatio,
		record.UeFeatureVector.SynRatio,
		record.UeFeatureVector.RstRatio,
	)

	return systemContent, userContent
}

// PredictSingleUE sends a single UE traffic record to LLM server for anomaly detection
// Uses OpenAI-compatible API with optimized key-value prompt format
func (c *LLMClient) PredictSingleUE(ctx context.Context, record *models.UeTrafficRecord) (*models.InferenceResult, error) {
	// Track request timing for diagnostics
	startTime := time.Now()
	defer func() {
		elapsed := time.Since(startTime)
		if elapsed > c.timeout/2 {
			logger.AnalyzerLog.Debugf("[LLMClient] ⚠️  %s: Slow request detected (%.2fs / %.2fs timeout)", 
				record.Supi, elapsed.Seconds(), c.timeout.Seconds())
		}
	}()

	// Build key-value format prompt
	systemContent, userContent := c.BuildSingleUEPrompt(record)

	// OpenAI Chat Completions API format (simple request for single UE)
	openAIReq := map[string]interface{}{
		"model": "qwen",
		"messages": []map[string]string{
			{"role": "system", "content": systemContent},
			{"role": "user", "content": userContent},
		},
		"temperature": c.temperature, // Configurable temperature
		"max_tokens":  c.maxTokens,   // Configurable max tokens
	}

	jsonData, err := json.Marshal(openAIReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/v1/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		// Enhanced error reporting with timing info
		elapsed := time.Since(startTime)
		logger.AnalyzerLog.Errorf("[LLMClient] ❌ %s: HTTP request failed after %.2fs (timeout: %.2fs)",
			record.Supi, elapsed.Seconds(), c.timeout.Seconds())
		logger.AnalyzerLog.Errorf("[LLMClient] Error details: %v", err)
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse OpenAI response
	var openAIResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(respBody, &openAIResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if len(openAIResp.Choices) == 0 {
		return nil, fmt.Errorf("empty response from LLM")
	}

	rawContent := openAIResp.Choices[0].Message.Content
	logger.AnalyzerLog.Debugf("[LLMClient] %s: Raw LLM response: %s", record.Supi, rawContent)

	// Extract risk score using regex (fault-tolerant)
	match := c.scoreRegex.FindStringSubmatch(rawContent)
	if len(match) < 2 {
		// No valid score found, return default (fail-open)
		logger.AnalyzerLog.Warnf("[LLMClient] ⚠️  %s: Failed to parse Risk Score from LLM response (regex mismatch)", record.Supi)
		logger.AnalyzerLog.Warnf("[LLMClient] Raw response: %s", rawContent)
		logger.AnalyzerLog.Warnf("[LLMClient] Applying fail-open: defaulting to score 0.1 (low risk)")
		return &models.InferenceResult{
			Supi:         record.Supi,
			AnomalyScore: 0.1,
		}, nil
	}

	score, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		logger.AnalyzerLog.Warnf("[LLMClient] ⚠️  %s: Failed to parse score string '%s': %v", record.Supi, match[1], err)
		logger.AnalyzerLog.Warnf("[LLMClient] Applying fail-open: defaulting to score 0.1 (low risk)")
		return &models.InferenceResult{
			Supi:         record.Supi,
			AnomalyScore: 0.1,
		}, nil
	}

	logger.AnalyzerLog.Debugf("[LLMClient] ✓ %s: Parsed anomaly score = %.2f", record.Supi, score)

	return &models.InferenceResult{
		Supi:         record.Supi,
		AnomalyScore: score,
	}, nil
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
