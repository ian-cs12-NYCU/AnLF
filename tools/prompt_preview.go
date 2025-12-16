package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/free5gc/anlf/internal/analyzer/detector"
	"github.com/free5gc/anlf/pkg/models"
)

func main() {
	// Parse command-line flags
	systemPromptPath := flag.String("prompt", "./prompts/anomaly_detection_single_ue.txt", "Path to system prompt file")
	showUserOnly := flag.Bool("user-only", false, "Show only user prompt (without system prompt)")
	showSystemOnly := flag.Bool("system-only", false, "Show only system prompt")
	includeGlobal := flag.Bool("global", true, "Include global network statistics in prompt")
	flag.Parse()

	fmt.Println("====================================================================")
	fmt.Println("              AnLF Prompt Preview Tool")
	fmt.Println("====================================================================")
	fmt.Printf("System Prompt Path: %s\n", *systemPromptPath)
	fmt.Printf("Mode: Template-Based Format (Placeholder Replacement)\n")
	fmt.Printf("Global Context: %v\n", *includeGlobal)
	fmt.Println("====================================================================")
	fmt.Println()

	// Create LLM client with the specified prompt path
	client := detector.NewLLMClient(detector.LLMClientConfig{
		SystemPromptPath: *systemPromptPath,
		ServerURL:        "http://dummy-url", // Not used for preview
	})

	// Generate sample UE and global statistics
	record := generateSampleRecord()
	var globalStats *models.GlobalNetworkStats
	if *includeGlobal {
		globalStats = generateSampleGlobalStats()
	}

	// Build single UE prompt with template replacement
	systemContent, userContent := client.BuildSingleUEPrompt(record, globalStats)

	// Display the results based on flags
	if *showSystemOnly {
		printSection("SYSTEM PROMPT", systemContent)
	} else if *showUserOnly {
		printSection("USER PROMPT (Key-Value Format)", userContent)
	} else {
		// Show combined prompt
		finalPrompt := strings.TrimSpace(systemContent + "\n\n" + userContent)
		fmt.Println("FINAL PROMPT")
		fmt.Println()
		fmt.Println("\033[41;97m [PROMPT START] \033[0m")
		if finalPrompt == "" {
			fmt.Println("(empty)")
		} else {
			fmt.Println(finalPrompt)
		}
		fmt.Println("\033[41;97m [PROMPT END] \033[0m")
		fmt.Println()
		printSection("STATISTICS", fmt.Sprintf(
			"System Prompt Length: %d chars\nUser Prompt Length: %d chars\nTotal Length: %d chars\nFormat: Template-Based (placeholder replacement)",
			len(systemContent), len(userContent), len(systemContent)+len(userContent),
		))
	}
}

func generateSampleRecord() *models.UeTrafficRecord {
	// Generate a sample UE record with attack characteristics
	return &models.UeTrafficRecord{
		Supi:      "imsi-2089300000000001",
		Timestamp: 1734350400,
		UeIp:      "10.60.0.1",
		UeFeatureVector: models.UeFeatureVector{
			LogPPS:      5.0, // High PPS (potential attack)
			AvgLen:      512.0,
			IcmpRatio:   0.01,
			TcpRatio:    0.6,
			UdpRatio:    0.39,
			SynRatio:    0.1,
			RstRatio:    0.01,
			NewFlowRate: 0.9, // High flow rate
			FanOut:      5.0,
		},
	}
}

func generateSampleGlobalStats() *models.GlobalNetworkStats {
	// Generate sample global network statistics
	return &models.GlobalNetworkStats{
		AvgLogPPS:   3.2,   // Average log10(PPS) across all UEs
		AvgFlowRate: 0.3,   // Average new flow rate
		AvgLen:      650.0, // Average packet size
	}
}

func printSection(title, content string) {
	// For prompt sections, print minimal header and wrap the content
	// with clear color tags so they won't be mistaken as separators.
	if title == "SYSTEM PROMPT" || strings.HasPrefix(title, "USER PROMPT") {
		fmt.Printf("%s\n\n", title)
		// Start tag (colored for terminal visibility)
		fmt.Println("\033[41;97m [PROMPT START] \033[0m")
		if content == "" {
			fmt.Println("(empty)")
		} else {
			fmt.Println(content)
		}
		// End tag (colored)
		fmt.Println("\033[41;97m [PROMPT END] \033[0m")
		return
	}

	// Fallback formatting for other sections (e.g., statistics)
	fmt.Println(strings.Repeat("─", 70))
	fmt.Printf("  %s\n", title)
	fmt.Println(strings.Repeat("─", 70))
	if content == "" {
		fmt.Println("(empty)")
	} else {
		fmt.Println(content)
	}
}
