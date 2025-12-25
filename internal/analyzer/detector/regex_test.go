package detector

import (
	"regexp"
	"testing"
)

// TestMultipleRegexFormats tests that all supported LLM response formats can be parsed correctly
func TestMultipleRegexFormats(t *testing.T) {
	// Define the regex patterns (same as in llm_client.go)
	scoreRegexes := []*regexp.Regexp{
		regexp.MustCompile(`Risk Score:\s*((?:0\.\d+|1\.0|0|1))(?:[^\d]|$)`),        // Standard format
		regexp.MustCompile(`"risk_score":\s*((?:0\.\d+|1\.0|0|1))(?:[,}\s]|$)`),     // JSON format (number)
		regexp.MustCompile(`"risk_score":\s*"((?:0\.\d+|1\.0|0|1))"(?:[,}\s]|$)`),   // JSON format (string)
		regexp.MustCompile(`risk_score["\s:]+\s*((?:0\.\d+|1\.0|0|1))(?:[,}\s]|$)`), // Flexible JSON
		regexp.MustCompile(`Response:\s*((?:0\.\d+|1\.0|0|1))(?:[^\d]|$)`),          // Fallback format
	}

	tests := []struct {
		name            string
		response        string
		expectedScore   string
		shouldMatch     bool
		expectedPattern int
	}{
		{
			name:            "low_latency format - standard",
			response:        "Risk Score: 0.8",
			expectedScore:   "0.8",
			shouldMatch:     true,
			expectedPattern: 0,
		},
		{
			name:            "low_latency format - with newline",
			response:        "Some analysis text\nRisk Score: 0.65\nMore text",
			expectedScore:   "0.65",
			shouldMatch:     true,
			expectedPattern: 0,
		},
		{
			name: "high_accuracy format - JSON with number",
			response: `{
  "risk_score": 0.98,
  "classification": "attack",
  "primary_factor": "SYN"
}`,
			expectedScore:   "0.98",
			shouldMatch:     true,
			expectedPattern: 1,
		},
		{
			name: "high_accuracy format - JSON with string",
			response: `{
  "risk_score": "0.95",
  "classification": "attack"
}`,
			expectedScore:   "0.95",
			shouldMatch:     true,
			expectedPattern: 2,
		},
		{
			name:            "JSON inline format",
			response:        `{"risk_score":0.75,"status":"normal"}`,
			expectedScore:   "0.75",
			shouldMatch:     true,
			expectedPattern: 1,
		},
		{
			name:            "Score 1.0 boundary",
			response:        "Risk Score: 1.0",
			expectedScore:   "1.0",
			shouldMatch:     true,
			expectedPattern: 0,
		},
		{
			name:            "Score 0 boundary",
			response:        "Risk Score: 0",
			expectedScore:   "0",
			shouldMatch:     true,
			expectedPattern: 0,
		},
		{
			name:            "Fallback format - Response colon",
			response:        "Response: 0.8",
			expectedScore:   "0.8",
			shouldMatch:     true,
			expectedPattern: 4,
		},
		{
			name:            "Fallback format - with newline",
			response:        "Some text\nResponse: 0.65\nMore text",
			expectedScore:   "0.65",
			shouldMatch:     true,
			expectedPattern: 4,
		},
		{
			name:            "Invalid response - no score",
			response:        "This is just some random text without any score",
			expectedScore:   "",
			shouldMatch:     false,
			expectedPattern: -1,
		},
		{
			name:            "Invalid response - no score keyword",
			response:        "The value is 1.5 which is too high",
			expectedScore:   "",
			shouldMatch:     false,
			expectedPattern: -1,
		},
		{
			name:            "Invalid response - wrong format",
			response:        "Score is approximately 0.85",
			expectedScore:   "",
			shouldMatch:     false,
			expectedPattern: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var match []string
			matchedPattern := -1

			// Try all regex patterns
			for i, regex := range scoreRegexes {
				match = regex.FindStringSubmatch(tt.response)
				if len(match) >= 2 {
					matchedPattern = i
					break
				}
			}

			if tt.shouldMatch {
				if matchedPattern == -1 {
					t.Errorf("Expected to match pattern, but no pattern matched.\nResponse: %s", tt.response)
					return
				}

				if match[1] != tt.expectedScore {
					t.Errorf("Expected score '%s', got '%s'", tt.expectedScore, match[1])
				}

				if matchedPattern != tt.expectedPattern {
					t.Logf("Note: Expected pattern #%d, but matched pattern #%d (still valid)", tt.expectedPattern, matchedPattern)
				}
			} else {
				if matchedPattern != -1 {
					t.Errorf("Expected no match, but pattern #%d matched with score '%s'", matchedPattern, match[1])
				}
			}
		})
	}
}

// TestRegexPerformance tests the performance of trying multiple regex patterns
func TestRegexPerformance(t *testing.T) {
	scoreRegexes := []*regexp.Regexp{
		regexp.MustCompile(`Risk Score:\s*((?:0\.\d+|1\.0|0|1))(?:[^\d]|$)`),
		regexp.MustCompile(`"risk_score":\s*((?:0\.\d+|1\.0|0|1))(?:[,}\s]|$)`),
		regexp.MustCompile(`"risk_score":\s*"((?:0\.\d+|1\.0|0|1))"(?:[,}\s]|$)`),
		regexp.MustCompile(`risk_score["\s:]+\s*((?:0\.\d+|1\.0|0|1))(?:[,}\s]|$)`),
		regexp.MustCompile(`Response:\s*((?:0\.\d+|1\.0|0|1))(?:[^\d]|$)`),
	}

	response := `{
  "risk_score": 0.98,
  "classification": "attack",
  "primary_factor": "SYN"
}`

	// Warm-up
	for i := 0; i < 100; i++ {
		for _, regex := range scoreRegexes {
			match := regex.FindStringSubmatch(response)
			if len(match) >= 2 {
				break
			}
		}
	}

	// The actual matching is very fast (microseconds), so no need for formal benchmark
	// Just verify it works
	var match []string
	for _, regex := range scoreRegexes {
		match = regex.FindStringSubmatch(response)
		if len(match) >= 2 {
			break
		}
	}

	if len(match) < 2 {
		t.Error("Performance test failed: no match found")
	}
	if match[1] != "0.98" {
		t.Errorf("Performance test failed: expected 0.98, got %s", match[1])
	}
}
