// testing_suite.go - Comprehensive security testing tools
package guard

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Test configuration structure
type TestSuite struct {
	BaseURL string     `json:"base_url"`
	Tests   []TestCase `json:"tests"`
}

type TestCase struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Target      string            `json:"target"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	QueryParams map[string]string `json:"query_params"`
	Expected    string            `json:"expected_result"`
	Concurrent  int               `json:"concurrent_requests"`
	Duration    int               `json:"duration_seconds"`
}

type TestResult struct {
	TestName     string        `json:"test_name"`
	Success      bool          `json:"success"`
	ResponseCode int           `json:"response_code"`
	ResponseTime time.Duration `json:"response_time"`
	Error        string        `json:"error,omitempty"`
	Blocked      bool          `json:"blocked"`
	Details      string        `json:"details"`
}

// Security test runner
func mai1n() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run testing_suite.go <test_config.json>")
		fmt.Println("Or: go run testing_suite.go generate")
		os.Exit(1)
	}

	if os.Args[1] == "generate" {
		generateTestConfig()
		return
	}

	configFile := os.Args[1]
	suite, err := loadTestSuite(configFile)
	if err != nil {
		log.Fatalf("Failed to load test suite: %v", err)
	}

	fmt.Printf("🔍 Starting security test suite against: %s\n", suite.BaseURL)
	fmt.Printf("📊 Running %d test cases...\n\n", len(suite.Tests))

	results := runTestSuite(suite)
	generateReport(results)
}

func loadTestSuite(filename string) (*TestSuite, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var suite TestSuite
	if err := json.Unmarshal(data, &suite); err != nil {
		return nil, err
	}

	return &suite, nil
}

func runTestSuite(suite *TestSuite) []TestResult {
	var allResults []TestResult
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	for i, test := range suite.Tests {
		fmt.Printf("[%d/%d] Running: %s (%s)\n", i+1, len(suite.Tests), test.Name, test.Type)

		var results []TestResult
		switch test.Type {
		case "single_request":
			result := runSingleRequest(client, suite.BaseURL, test)
			results = append(results, result)
		case "rate_limit":
			results = runRateLimitTest(client, suite.BaseURL, test)
		case "vulnerability":
			result := runVulnerabilityTest(client, suite.BaseURL, test)
			results = append(results, result)
		case "load":
			results = runLoadTest(client, suite.BaseURL, test)
		case "ddos_simulation":
			results = runDDOSSimulation(client, suite.BaseURL, test)
		default:
			fmt.Printf("❌ Unknown test type: %s\n", test.Type)
			continue
		}

		allResults = append(allResults, results...)
		time.Sleep(1 * time.Second) // Pause between tests
	}

	return allResults
}

func runSingleRequest(client *http.Client, baseURL string, test TestCase) TestResult {
	start := time.Now()

	req, err := http.NewRequest(test.Method, baseURL+test.Target, strings.NewReader(test.Body))
	if err != nil {
		return TestResult{
			TestName: test.Name,
			Success:  false,
			Error:    err.Error(),
		}
	}

	// Add headers
	for key, value := range test.Headers {
		req.Header.Set(key, value)
	}

	// Add query parameters
	q := req.URL.Query()
	for key, value := range test.QueryParams {
		q.Add(key, value)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	responseTime := time.Since(start)

	if err != nil {
		return TestResult{
			TestName:     test.Name,
			Success:      false,
			ResponseTime: responseTime,
			Error:        err.Error(),
		}
	}
	defer resp.Body.Close()

	blocked := resp.StatusCode == 403 || resp.StatusCode == 429 || resp.StatusCode == 401
	expectedBlocked := test.Expected == "blocked"

	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)

	return TestResult{
		TestName:     test.Name,
		Success:      blocked == expectedBlocked,
		ResponseCode: resp.StatusCode,
		ResponseTime: responseTime,
		Blocked:      blocked,
		Details:      fmt.Sprintf("Response body: %s", bodyStr),
	}
}

func runRateLimitTest(client *http.Client, baseURL string, test TestCase) []TestResult {
	var results []TestResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	fmt.Printf("   └─ Sending %d concurrent requests...\n", test.Concurrent)

	for i := 0; i < test.Concurrent; i++ {
		wg.Add(1)
		go func(reqNum int) {
			defer wg.Done()

			testName := fmt.Sprintf("%s_req_%d", test.Name, reqNum)
			result := runSingleRequest(client, baseURL, TestCase{
				Name:        testName,
				Type:        "single_request",
				Target:      test.Target,
				Method:      test.Method,
				Headers:     test.Headers,
				QueryParams: test.QueryParams,
				Expected:    test.Expected,
			})

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(i)

		// Rapid-fire requests to trigger rate limiting
		time.Sleep(10 * time.Millisecond)
	}

	wg.Wait()
	return results
}

func runVulnerabilityTest(client *http.Client, baseURL string, test TestCase) TestResult {
	return runSingleRequest(client, baseURL, test)
}

func runLoadTest(client *http.Client, baseURL string, test TestCase) []TestResult {
	var results []TestResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	duration := time.Duration(test.Duration) * time.Second
	endTime := time.Now().Add(duration)

	fmt.Printf("   └─ Load test: %d workers for %d seconds...\n", test.Concurrent, test.Duration)

	for i := 0; i < test.Concurrent; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			reqCount := 0

			for time.Now().Before(endTime) {
				testName := fmt.Sprintf("%s_worker_%d_req_%d", test.Name, workerID, reqCount)
				result := runSingleRequest(client, baseURL, TestCase{
					Name:        testName,
					Type:        "single_request",
					Target:      test.Target,
					Method:      test.Method,
					Headers:     test.Headers,
					QueryParams: test.QueryParams,
					Expected:    test.Expected,
				})

				mu.Lock()
				results = append(results, result)
				mu.Unlock()

				reqCount++
				time.Sleep(time.Duration(rand.Intn(200)) * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
	return results
}

func runDDOSSimulation(client *http.Client, baseURL string, test TestCase) []TestResult {
	var results []TestResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	duration := time.Duration(test.Duration) * time.Second
	endTime := time.Now().Add(duration)

	fmt.Printf("   └─ DDoS simulation: %d concurrent attackers for %d seconds...\n", test.Concurrent, test.Duration)

	// Simulate aggressive attack patterns
	for i := 0; i < test.Concurrent; i++ {
		wg.Add(1)
		go func(attackerID int) {
			defer wg.Done()
			reqCount := 0

			for time.Now().Before(endTime) {
				testName := fmt.Sprintf("%s_attacker_%d_req_%d", test.Name, attackerID, reqCount)

				// Vary the attack patterns
				target := test.Target
				if attackerID%3 == 0 {
					target = "/test/login" // Brute force simulation
				} else if attackerID%3 == 1 {
					target = "/test/vulnerable?id=1' OR '1'='1" // SQL injection
				}

				result := runSingleRequest(client, baseURL, TestCase{
					Name:        testName,
					Type:        "single_request",
					Target:      target,
					Method:      test.Method,
					Headers:     test.Headers,
					QueryParams: test.QueryParams,
					Expected:    "blocked", // Should be blocked
				})

				mu.Lock()
				results = append(results, result)
				mu.Unlock()

				reqCount++
				// Very aggressive - minimal delay
				time.Sleep(time.Duration(rand.Intn(50)) * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
	return results
}

func generateReport(results []TestResult) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("🧪 SECURITY TEST REPORT")
	fmt.Println(strings.Repeat("=", 60))

	totalTests := len(results)
	passed := 0
	blocked := 0
	var totalResponseTime time.Duration

	statusCounts := make(map[int]int)

	for _, result := range results {
		if result.Success {
			passed++
		}
		if result.Blocked {
			blocked++
		}
		totalResponseTime += result.ResponseTime
		statusCounts[result.ResponseCode]++
	}

	fmt.Printf("📊 SUMMARY:\n")
	fmt.Printf("   Total Tests: %d\n", totalTests)
	fmt.Printf("   Passed: %d (%.1f%%)\n", passed, float64(passed)/float64(totalTests)*100)
	fmt.Printf("   Blocked: %d (%.1f%%)\n", blocked, float64(blocked)/float64(totalTests)*100)
	if totalTests > 0 {
		fmt.Printf("   Avg Response Time: %v\n", totalResponseTime/time.Duration(totalTests))
	}

	fmt.Println("\n📈 HTTP STATUS CODES:")
	for status, count := range statusCounts {
		percentage := float64(count) / float64(totalTests) * 100
		fmt.Printf("   %d: %d requests (%.1f%%)\n", status, count, percentage)
	}

	// Detailed results
	fmt.Println("\n🔍 DETAILED RESULTS:")
	failedTests := 0
	for _, result := range results {
		status := "✅ PASS"
		if !result.Success {
			status = "❌ FAIL"
			failedTests++
		}

		fmt.Printf("   %s %s (%.2fms) - HTTP %d\n",
			status, result.TestName, float64(result.ResponseTime.Nanoseconds())/1000000, result.ResponseCode)

		if result.Error != "" {
			fmt.Printf("      Error: %s\n", result.Error)
		}
	}

	// Security assessment
	fmt.Println("\n🛡️ SECURITY ASSESSMENT:")
	if blocked > totalTests/2 {
		fmt.Println("   ✅ Good: High blocking rate indicates active protection")
	} else if blocked > totalTests/4 {
		fmt.Println("   ⚠️  Moderate: Some requests blocked, may need tuning")
	} else {
		fmt.Println("   ❌ Concerning: Low blocking rate, protection may be ineffective")
	}

	// Save results to file
	jsonResults, _ := json.MarshalIndent(results, "", "  ")
	filename := fmt.Sprintf("test_results_%d.json", time.Now().Unix())
	ioutil.WriteFile(filename, jsonResults, 0644)
	fmt.Printf("\n📄 Detailed results saved to: %s\n", filename)
}

func generateTestConfig() {
	config := TestSuite{
		BaseURL: "http://localhost:8080",
		Tests: []TestCase{
			{
				Name:     "basic_connectivity",
				Type:     "single_request",
				Target:   "/",
				Method:   "GET",
				Headers:  map[string]string{"User-Agent": "Security-Tester/1.0"},
				Expected: "allowed",
			},
			{
				Name:       "rate_limit_test",
				Type:       "rate_limit",
				Target:     "/",
				Method:     "GET",
				Headers:    map[string]string{"User-Agent": "RateLimit-Tester/1.0"},
				Concurrent: 150,
				Expected:   "blocked", // Should trigger rate limiting
			},
			{
				Name:    "sql_injection_test",
				Type:    "vulnerability",
				Target:  "/test/vulnerable",
				Method:  "GET",
				Headers: map[string]string{"User-Agent": "VulnTest/1.0"},
				QueryParams: map[string]string{
					"id": "1' OR '1'='1",
				},
				Expected: "blocked",
			},
			{
				Name:    "xss_test",
				Type:    "vulnerability",
				Target:  "/test/vulnerable",
				Method:  "GET",
				Headers: map[string]string{"User-Agent": "VulnTest/1.0"},
				QueryParams: map[string]string{
					"comment": "<script>alert('XSS')</script>",
				},
				Expected: "blocked",
			},
			{
				Name:    "path_traversal_test",
				Type:    "vulnerability",
				Target:  "/test/vulnerable",
				Method:  "GET",
				Headers: map[string]string{"User-Agent": "VulnTest/1.0"},
				QueryParams: map[string]string{
					"file": "../../../etc/passwd",
				},
				Expected: "blocked",
			},
			{
				Name:       "brute_force_simulation",
				Type:       "rate_limit",
				Target:     "/test/login",
				Method:     "POST",
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       `{"username":"admin","password":"test123"}`,
				Concurrent: 20,
				Expected:   "blocked",
			},
			{
				Name:       "load_test",
				Type:       "load",
				Target:     "/api/status",
				Method:     "GET",
				Headers:    map[string]string{"User-Agent": "LoadTest/1.0"},
				Concurrent: 10,
				Duration:   30,
				Expected:   "mixed", // Some should pass, some might be limited
			},
			{
				Name:       "ddos_simulation",
				Type:       "ddos_simulation",
				Target:     "/",
				Method:     "GET",
				Headers:    map[string]string{"User-Agent": "AttackBot/1.0"},
				Concurrent: 50,
				Duration:   60,
				Expected:   "blocked",
			},
			{
				Name:     "suspicious_user_agent",
				Type:     "single_request",
				Target:   "/",
				Method:   "GET",
				Headers:  map[string]string{"User-Agent": ""},
				Expected: "blocked", // Should trigger behavioral detection
			},
			{
				Name:     "large_payload_test",
				Type:     "single_request",
				Target:   "/",
				Method:   "POST",
				Headers:  map[string]string{"Content-Type": "application/json"},
				Body:     strings.Repeat("A", 15*1024*1024), // 15MB payload
				Expected: "blocked",
			},
		},
	}

	data, _ := json.MarshalIndent(config, "", "  ")
	filename := "security_tests.json"
	err := ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		log.Fatalf("Failed to write config file: %v", err)
	}

	fmt.Printf("✅ Generated test configuration: %s\n", filename)
	fmt.Println("\nTo run tests:")
	fmt.Printf("go run testing_suite.go %s\n", filename)
}
