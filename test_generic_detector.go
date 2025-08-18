package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func main() {
	baseURL := "http://localhost:8080"

	// Test cases for the generic detector
	testCases := []struct {
		name        string
		url         string
		userAgent   string
		forwardedIP string
		expected    string
	}{
		{
			name:        "Normal Request",
			url:         "/demo/user-info",
			userAgent:   "Mozilla/5.0",
			forwardedIP: "10.0.0.1",
			expected:    "should pass",
		},
		{
			name:        "SQL Injection in Query",
			url:         "/demo/user-info?id=1' UNION SELECT * FROM users--",
			userAgent:   "Mozilla/5.0",
			forwardedIP: "10.0.0.2",
			expected:    "should be blocked by generic detector SQL rule",
		},
		{
			name:        "XSS in Path",
			url:         "/demo/<script>alert('xss')</script>",
			userAgent:   "Mozilla/5.0",
			forwardedIP: "10.0.0.3",
			expected:    "should be blocked by generic detector XSS rule",
		},
		{
			name:        "Admin Path Access",
			url:         "/admin/dashboard",
			userAgent:   "Mozilla/5.0",
			forwardedIP: "10.0.0.4",
			expected:    "should be blocked by generic detector admin rule",
		},
		{
			name:        "Suspicious User Agent",
			url:         "/demo/user-info",
			userAgent:   "BadBot/1.0",
			forwardedIP: "10.0.0.5",
			expected:    "should trigger warning by generic detector bot rule",
		},
	}

	fmt.Println("Testing Generic Detector Rules...")
	fmt.Println("================================")

	for i, test := range testCases {
		fmt.Printf("\n%d. %s\n", i+1, test.name)
		fmt.Printf("   URL: %s\n", test.url)
		fmt.Printf("   Expected: %s\n", test.expected)

		// Create request
		req, err := http.NewRequest("GET", baseURL+test.url, nil)
		if err != nil {
			fmt.Printf("   Error creating request: %v\n", err)
			continue
		}

		// Set headers
		req.Header.Set("User-Agent", test.userAgent)
		req.Header.Set("X-Forwarded-For", test.forwardedIP)

		// Make request
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("   Error making request: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		// Read response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("   Error reading response: %v\n", err)
			continue
		}

		// Print results
		fmt.Printf("   Status: %d %s\n", resp.StatusCode, resp.Status)
		fmt.Printf("   Security Scan: %s\n", resp.Header.Get("X-Security-Scan"))
		fmt.Printf("   Threat Level: %s\n", resp.Header.Get("X-Threat-Level"))

		// Parse JSON response if possible
		var jsonResp map[string]interface{}
		if err := json.Unmarshal(body, &jsonResp); err == nil {
			if blocked, ok := jsonResp["blocked"].(bool); ok && blocked {
				fmt.Printf("   Result: BLOCKED - %s\n", jsonResp["reason"])
			} else if errorMsg, ok := jsonResp["error"].(string); ok {
				fmt.Printf("   Result: ERROR - %s\n", errorMsg)
			} else {
				fmt.Printf("   Result: ALLOWED\n")
			}
		} else {
			fmt.Printf("   Result: Non-JSON response\n")
		}

		// Wait a bit between requests
		time.Sleep(500 * time.Millisecond)
	}

	// Get final metrics
	fmt.Println("\n\nFinal Metrics:")
	fmt.Println("==============")

	req, err := http.NewRequest("GET", baseURL+"/metrics", nil)
	if err != nil {
		fmt.Printf("Error creating metrics request: %v\n", err)
		return
	}
	req.Header.Set("X-Forwarded-For", "10.0.0.99")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error getting metrics: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading metrics: %v\n", err)
		return
	}

	var metrics map[string]interface{}
	if err := json.Unmarshal(body, &metrics); err == nil {
		if plugins, ok := metrics["plugins"].(map[string]interface{}); ok {
			if genericDetector, ok := plugins["generic_detector"].(map[string]interface{}); ok {
				fmt.Printf("Generic Detector Metrics:\n")
				for key, value := range genericDetector {
					fmt.Printf("  %s: %v\n", key, value)
				}
			}
		}
	}
}
