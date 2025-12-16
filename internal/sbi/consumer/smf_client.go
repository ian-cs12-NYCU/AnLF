package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/free5gc/anlf/internal/logger"
)

// SMF OAM API response structures
type SmfOamResponse struct {
	PoolSize      int                       `json:"poolSize"`
	SmContexts    map[string]PduSessionInfo `json:"smContexts"`
	TotalContexts int                       `json:"totalContexts"`
	Message       string                    `json:"message,omitempty"` // For "No SM contexts found"
}

type PduSessionInfo struct {
	Supi         string `json:"supi"`
	PduSessionId string `json:"pduSessionId"`
	PduAddress   string `json:"pduAddress"` // UE IP address
}

// SMFClient provides UE IP to SUPI mapping from real SMF OAM API
type SMFClient struct {
	smfUrl       string // SMF OAM API base URL
	httpClient   *http.Client
	ueTable      map[string]string // key: UE IP, value: SUPI
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	pollInterval time.Duration
	pollCounter  int // Counter for periodic status reports
}

// NewSMFClient creates a new SMFClient instance
func NewSMFClient(smfUrl string, pollInterval time.Duration) *SMFClient {
	ctx, cancel := context.WithCancel(context.Background())

	return &SMFClient{
		smfUrl: smfUrl,
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
		},
		ueTable:      make(map[string]string),
		ctx:          ctx,
		cancel:       cancel,
		pollInterval: pollInterval,
	}
}

// Start begins periodic polling of SMF OAM API (Lifecycle interface)
func (s *SMFClient) Start(ctx context.Context) error {
	logger.SmfLog.Infof("Starting SMF client with poll interval: %v", s.pollInterval)

	// Do first fetch immediately
	if err := s.fetchUeData(); err != nil {
		logger.SmfLog.Warnf("Initial SMF fetch failed: %v", err)
	}

	// Start periodic polling
	go s.pollLoop()

	return nil
}

// Stop stops the periodic polling (Lifecycle interface)
func (s *SMFClient) Stop(timeout time.Duration) error {
	logger.SmfLog.Info("Stopping SMF client...")
	s.cancel()
	return nil
}

// Name returns the component name (Lifecycle interface)
func (s *SMFClient) Name() string {
	return "SMFClient"
}

// pollLoop periodically fetches UE data from SMF
func (s *SMFClient) pollLoop() {
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if err := s.fetchUeData(); err != nil {
				logger.ConsumerLog.Warnf("Failed to fetch UE data from SMF: %v", err)
			}
		}
	}
}

// fetchUeData fetches UE PDU session info from SMF OAM API
func (s *SMFClient) fetchUeData() error {
	// Build request URL
	url := fmt.Sprintf("%s/nsmf-oam/v1/ue-pdu-session-info/", s.smfUrl)

	req, err := http.NewRequestWithContext(s.ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Handle 404 - no SM contexts
	if resp.StatusCode == http.StatusNotFound {
		logger.SmfLog.Debug("No SM contexts found on SMF (404)")
		s.mu.Lock()
		prevCount := len(s.ueTable)
		s.ueTable = make(map[string]string) // Clear table
		s.mu.Unlock()
		if prevCount > 0 {
			logger.SmfLog.Warnf("=== SMF UE TABLE CLEARED (was %d entries) ===", prevCount)
		}
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var smfResp SmfOamResponse
	if err := json.Unmarshal(body, &smfResp); err != nil {
		return fmt.Errorf("failed to parse JSON response: %w", err)
	}

	// Build new UE table
	newTable := make(map[string]string)
	for _, pduInfo := range smfResp.SmContexts {
		if pduInfo.PduAddress != "" && pduInfo.Supi != "" {
			newTable[pduInfo.PduAddress] = pduInfo.Supi
		}
	}

	// Update table atomically and log prominent message when created/updated
	s.mu.Lock()
	prevCount := len(s.ueTable)
	s.ueTable = newTable
	newCount := len(newTable)
	s.pollCounter++
	currentPollCount := s.pollCounter
	s.mu.Unlock()

	// Log status based on changes
	if prevCount == 0 && newCount > 0 {
		logger.SmfLog.Infof("╔═══════════════════════════════════════════════════════════════════╗")
		logger.SmfLog.Infof("║ SMF UE TABLE CREATED: %d entries                                  ", newCount)
		logger.SmfLog.Infof("╚═══════════════════════════════════════════════════════════════════╝")
		s.logUeTableSnapshot(newTable)
	} else if newCount != prevCount {
		logger.SmfLog.Infof("╔═══════════════════════════════════════════════════════════════════╗")
		logger.SmfLog.Infof("║ SMF UE TABLE UPDATED: %d entries (was %d)                         ", newCount, prevCount)
		logger.SmfLog.Infof("╚═══════════════════════════════════════════════════════════════════╝")
		s.logUeTableSnapshot(newTable)
	} else if currentPollCount%6 == 0 {
		// Every 6 polls (30 seconds with 5s interval), show status even if unchanged
		logger.SmfLog.Infof("╔═══════════════════════════════════════════════════════════════════╗")
		logger.SmfLog.Infof("║ SMF UE TABLE STATUS: %d entries (unchanged, poll #%d)             ", newCount, currentPollCount)
		logger.SmfLog.Infof("╚═══════════════════════════════════════════════════════════════════╝")
	} else {
		logger.SmfLog.Debugf("SMF UE table unchanged: %d entries (poll #%d)", newCount, currentPollCount)
	}

	return nil
}

// logUeTableSnapshot logs a snapshot of the UE table (first few entries)
func (s *SMFClient) logUeTableSnapshot(table map[string]string) {
	if len(table) == 0 {
		return
	}

	// Get sorted list for consistent logging
	type ueEntry struct {
		ip   string
		supi string
	}
	entries := make([]ueEntry, 0, len(table))
	for ip, supi := range table {
		entries = append(entries, ueEntry{ip: ip, supi: supi})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].supi < entries[j].supi
	})

	// Log first 3 and last 3 entries as examples
	logger.SmfLog.Infof("  Sample UE entries:")
	maxShow := 3
	if len(entries) < maxShow {
		maxShow = len(entries)
	}
	for i := 0; i < maxShow; i++ {
		logger.SmfLog.Infof("    • %s → %s", entries[i].ip, entries[i].supi)
	}
	if len(entries) > 6 {
		logger.SmfLog.Infof("    ... (%d more entries) ...", len(entries)-6)
		for i := len(entries) - 3; i < len(entries); i++ {
			logger.SmfLog.Infof("    • %s → %s", entries[i].ip, entries[i].supi)
		}
	} else if len(entries) > 3 {
		for i := maxShow; i < len(entries); i++ {
			logger.SmfLog.Infof("    • %s → %s", entries[i].ip, entries[i].supi)
		}
	}
}

// GetSupi returns SUPI for given UE IP, returns "unknown" if not found
func (s *SMFClient) GetSupi(ueIp string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if supi, ok := s.ueTable[ueIp]; ok {
		return supi
	}
	return "unknown"
}

// GetUeCount returns the number of UEs in the table
func (s *SMFClient) GetUeCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ueTable)
}

// GetAllUeIps returns a slice of all known UE IPs, sorted by SUPI
func (s *SMFClient) GetAllUeIps() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Create slice of IP-SUPI pairs for sorting
	type ueEntry struct {
		ip   string
		supi string
	}

	entries := make([]ueEntry, 0, len(s.ueTable))
	for ip, supi := range s.ueTable {
		entries = append(entries, ueEntry{ip: ip, supi: supi})
	}

	// Sort by SUPI
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].supi < entries[j].supi
	})

	// Extract sorted IPs
	ips := make([]string, len(entries))
	for i, entry := range entries {
		ips[i] = entry.ip
	}

	return ips
}
