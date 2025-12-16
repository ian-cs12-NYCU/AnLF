package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/free5gc/anlf/internal/analyzer/detector"
	"github.com/free5gc/anlf/pkg/models"
)

func main() {
	// Parse command-line flags
	systemPromptPath := flag.String("prompt", "./prompts/anomaly_detection_basic.txt", "Path to system prompt file")
	numUEs := flag.Int("ues", 3, "Number of sample UEs to generate")
	showUserOnly := flag.Bool("user-only", false, "Show only user prompt (without system prompt)")
	showSystemOnly := flag.Bool("system-only", false, "Show only system prompt")
	flag.Parse()

	fmt.Println("====================================================================")
	fmt.Println("              AnLF Prompt Preview Tool")
	fmt.Println("====================================================================")
	fmt.Printf("System Prompt Path: %s\n", *systemPromptPath)
	fmt.Printf("Sample UEs: %d\n", *numUEs)
	fmt.Println("====================================================================\n")

	// Create LLM client with the specified prompt path
	client := detector.NewLLMClient(detector.LLMClientConfig{
		SystemPromptPath: *systemPromptPath,
		ServerURL:        "http://dummy-url", // Not used for preview
	})

	// Generate sample UE records
	records := generateSampleRecords(*numUEs)

	// Build the prompt
	systemContent, userContent, err := client.BuildPrompt(records)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building prompt: %v\n", err)
		os.Exit(1)
	}

	// Display the results based on flags
	if *showSystemOnly {
		printSection("SYSTEM PROMPT", systemContent)
	} else if *showUserOnly {
		printSection("USER PROMPT (UE Data)", userContent)
	} else {
		// Show combined prompt (system + user) wrapped with a single colored tag
		finalPrompt := strings.TrimSpace(systemContent + "\n\n" + userContent)
		fmt.Println("FINAL PROMPT")
		fmt.Println()
		// Colored start marker
		fmt.Println("\033[41;97m [PROMPT START] \033[0m")
		if finalPrompt == "" {
			fmt.Println("(empty)")
		} else {
			fmt.Println(finalPrompt)
		}
		// Colored end marker
		fmt.Println("\033[41;97m [PROMPT END] \033[0m")
		fmt.Println()
		printSection("STATISTICS", fmt.Sprintf(
			"System Prompt Length: %d chars\nUser Prompt Length: %d chars\nTotal Length: %d chars",
			len(systemContent), len(userContent), len(systemContent)+len(userContent),
		))
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

func generateSampleRecords(n int) []*models.UeTrafficRecord {
	records := make([]*models.UeTrafficRecord, n)
	for i := 0; i < n; i++ {
		// Generate diverse sample data: some normal, some potentially anomalous
		isAttacker := i%3 == 0 // Every 3rd UE is a potential attacker

		logPPS := 2.0 + float64(i)*0.5
		newFlowRate := 0.1 + float64(i)*0.05

		if isAttacker {
			logPPS = 5.0 + float64(i)*0.2       // Very high PPS (log scale)
			newFlowRate = 0.9 + float64(i)*0.01 // High new flow rate
		}

		records[i] = &models.UeTrafficRecord{
			Supi:      fmt.Sprintf("imsi-20893000000000%02d", i+1),
			Timestamp: 1734350400 + int64(i)*60, // Sequential timestamps
			UeIp:      fmt.Sprintf("10.60.0.%d", i+1),
			UeFeatureVector: models.UeFeatureVector{
				LogPPS:      logPPS,
				AvgLen:      512.0 + float64(i)*50,
				IcmpRatio:   0.01,
				TcpRatio:    0.6 + float64(i)*0.05,
				UdpRatio:    0.39 - float64(i)*0.05,
				SynRatio:    0.1 + float64(i)*0.02,
				RstRatio:    0.01,
				NewFlowRate: newFlowRate,
				FanOut:      float64(5 + i),
			},
		}
	}
	return records
}
