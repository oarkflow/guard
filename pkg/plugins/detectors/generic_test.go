package detectors

import (
	"context"
	"testing"

	"github.com/oarkflow/guard/pkg/plugins"
)

func TestGenericDetectorWithExistingConfigs(t *testing.T) {
	// Test SQL Injection patterns (from sql-injection-rules.json)
	t.Run("SQL Injection Detection", func(t *testing.T) {
		detector := NewGenericDetector()

		// Configure with SQL injection rules similar to existing config
		config := map[string]any{
			"rules": []any{
				map[string]any{
					"id":          "sql_injection_pattern",
					"name":        "SQL Injection Pattern",
					"description": "Detects common SQL injection patterns",
					"enabled":     true,
					"type":        "pattern",
					"severity":    8,
					"confidence":  0.8,
					"priority":    90,
					"conditions": []any{
						map[string]any{
							"field":    "path",
							"operator": "regex",
							"value":    "(?i)(union\\s+select|select\\s+.*\\s+from|insert\\s+into|delete\\s+from|drop\\s+table|create\\s+table)",
						},
					},
					"actions": []any{"block_action"},
					"tags":    []any{"sql_injection", "web_attack", "injection"},
				},
			},
		}

		err := detector.Initialize(config)
		if err != nil {
			t.Fatalf("Failed to initialize detector: %v", err)
		}

		// Debug: Check if rules were loaded
		rules := detector.GetRules()
		if len(rules) == 0 {
			t.Fatalf("No rules loaded")
		}
		t.Logf("Loaded %d rules", len(rules))
		t.Logf("Rule: %+v", rules[0])

		// Test SQL injection in path
		reqCtx := &plugins.RequestContext{
			IP:        "192.168.1.1",
			UserAgent: "Mozilla/5.0",
			Method:    "GET",
			Path:      "/users?id=1' UNION SELECT * FROM users--",
			Headers:   make(map[string]string),
			QueryParams: map[string]string{
				"id": "1' UNION SELECT * FROM users--",
			},
		}

		result := detector.Detect(context.Background(), reqCtx)

		t.Logf("Detection result: Threat=%v, Severity=%d, Confidence=%f, Details=%s",
			result.Threat, result.Severity, result.Confidence, result.Details)

		if !result.Threat {
			t.Error("Expected SQL injection to be detected as threat")
		}

		if result.Severity != 8 {
			t.Errorf("Expected severity 8, got %d", result.Severity)
		}

		if result.Confidence != 0.8 {
			t.Errorf("Expected confidence 0.8, got %f", result.Confidence)
		}

		// Check tags
		expectedTags := []string{"sql_injection", "web_attack", "injection"}
		if len(result.Tags) != len(expectedTags) {
			t.Errorf("Expected %d tags, got %d", len(expectedTags), len(result.Tags))
		}
	})

	// Test XSS patterns (from xss-rules.json)
	t.Run("XSS Detection", func(t *testing.T) {
		detector := NewGenericDetector()

		config := map[string]any{
			"rules": []any{
				map[string]any{
					"id":          "xss_pattern",
					"name":        "XSS Pattern",
					"description": "Detects common XSS patterns",
					"enabled":     true,
					"type":        "pattern",
					"severity":    7,
					"confidence":  0.7,
					"priority":    85,
					"conditions": []any{
						map[string]any{
							"field":    "path",
							"operator": "regex",
							"value":    "(?i)<\\s*script[^>]*>",
						},
					},
					"actions": []any{"block_action"},
					"tags":    []any{"xss", "web_attack", "injection"},
				},
			},
		}

		err := detector.Initialize(config)
		if err != nil {
			t.Fatalf("Failed to initialize detector: %v", err)
		}

		// Test XSS in path
		reqCtx := &plugins.RequestContext{
			IP:        "192.168.1.2",
			UserAgent: "Mozilla/5.0",
			Method:    "GET",
			Path:      "/search?q=<script>alert('xss')</script>",
			Headers:   make(map[string]string),
			QueryParams: map[string]string{
				"q": "<script>alert('xss')</script>",
			},
		}

		result := detector.Detect(context.Background(), reqCtx)

		if !result.Threat {
			t.Error("Expected XSS to be detected as threat")
		}

		if result.Severity != 7 {
			t.Errorf("Expected severity 7, got %d", result.Severity)
		}
	})

	// Test multiple conditions with logical operators
	t.Run("Complex Conditions", func(t *testing.T) {
		detector := NewGenericDetector()

		config := map[string]any{
			"rules": []any{
				map[string]any{
					"id":          "admin_access_rule",
					"name":        "Admin Access Rule",
					"description": "Blocks admin access from non-admin IPs",
					"enabled":     true,
					"type":        "access_control",
					"severity":    6,
					"confidence":  0.9,
					"priority":    80,
					"conditions": []any{
						map[string]any{
							"field":    "path",
							"operator": "starts_with",
							"value":    "/admin",
						},
					},
					"actions": []any{"block_action"},
					"tags":    []any{"unauthorized_access", "admin_panel"},
				},
			},
		}

		err := detector.Initialize(config)
		if err != nil {
			t.Fatalf("Failed to initialize detector: %v", err)
		}

		// Test admin path access
		reqCtx := &plugins.RequestContext{
			IP:          "192.168.1.3",
			UserAgent:   "Mozilla/5.0",
			Method:      "GET",
			Path:        "/admin/dashboard",
			Headers:     make(map[string]string),
			QueryParams: make(map[string]string),
		}

		result := detector.Detect(context.Background(), reqCtx)

		if !result.Threat {
			t.Error("Expected admin access to be detected as threat")
		}

		if result.Confidence != 0.9 {
			t.Errorf("Expected confidence 0.9, got %f", result.Confidence)
		}
	})

	// Test header-based detection
	t.Run("Header Detection", func(t *testing.T) {
		detector := NewGenericDetector()

		config := map[string]any{
			"rules": []any{
				map[string]any{
					"id":          "suspicious_user_agent",
					"name":        "Suspicious User Agent",
					"description": "Detects suspicious user agents",
					"enabled":     true,
					"type":        "user_agent",
					"severity":    5,
					"confidence":  0.6,
					"priority":    75,
					"conditions": []any{
						map[string]any{
							"field":    "user_agent",
							"operator": "regex",
							"value":    "(?i)bot",
						},
					},
					"actions": []any{"warning_action"},
					"tags":    []any{"suspicious", "bot"},
				},
			},
		}

		err := detector.Initialize(config)
		if err != nil {
			t.Fatalf("Failed to initialize detector: %v", err)
		}

		// Test suspicious user agent
		reqCtx := &plugins.RequestContext{
			IP:        "192.168.1.4",
			UserAgent: "BadBot/1.0",
			Method:    "GET",
			Path:      "/api/data",
			Headers: map[string]string{
				"User-Agent": "BadBot/1.0",
			},
			QueryParams: make(map[string]string),
		}

		result := detector.Detect(context.Background(), reqCtx)

		if !result.Threat {
			t.Error("Expected suspicious user agent to be detected as threat")
		}

		if result.Severity != 5 {
			t.Errorf("Expected severity 5, got %d", result.Severity)
		}
	})

	// Test that normal requests pass through
	t.Run("Normal Request", func(t *testing.T) {
		detector := NewGenericDetector()

		config := map[string]any{
			"rules": []any{
				map[string]any{
					"id":          "sql_injection_pattern",
					"name":        "SQL Injection Pattern",
					"description": "Detects common SQL injection patterns",
					"enabled":     true,
					"type":        "pattern",
					"severity":    8,
					"confidence":  0.8,
					"priority":    90,
					"conditions": []any{
						map[string]any{
							"field":    "path",
							"operator": "regex",
							"value":    "(?i)(union\\s+select|select\\s+.*\\s+from)",
						},
					},
					"actions": []any{"block_action"},
					"tags":    []any{"sql_injection"},
				},
			},
		}

		err := detector.Initialize(config)
		if err != nil {
			t.Fatalf("Failed to initialize detector: %v", err)
		}

		// Test normal request
		reqCtx := &plugins.RequestContext{
			IP:        "192.168.1.5",
			UserAgent: "Mozilla/5.0",
			Method:    "GET",
			Path:      "/api/users/123",
			Headers:   make(map[string]string),
			QueryParams: map[string]string{
				"format": "json",
			},
		}

		result := detector.Detect(context.Background(), reqCtx)

		if result.Threat {
			t.Error("Expected normal request to not be detected as threat")
		}

		if result.Severity != 0 {
			t.Errorf("Expected severity 0, got %d", result.Severity)
		}
	})
}

func TestGenericDetectorRuleManagement(t *testing.T) {
	detector := NewGenericDetector()

	// Initialize with empty rules
	err := detector.Initialize(map[string]any{"rules": []any{}})
	if err != nil {
		t.Fatalf("Failed to initialize detector: %v", err)
	}

	// Test adding a rule
	rule := GenericRule{
		ID:          "test_rule",
		Name:        "Test Rule",
		Description: "Test rule for unit testing",
		Enabled:     true,
		Type:        "test",
		Severity:    5,
		Confidence:  0.8,
		Priority:    50,
		Conditions: []RuleCondition{
			{
				Field:    "path",
				Operator: "equals",
				Value:    "/test",
			},
		},
		Actions: []string{"warning_action"},
		Tags:    []string{"test"},
	}

	err = detector.AddRule(rule)
	if err != nil {
		t.Fatalf("Failed to add rule: %v", err)
	}

	// Test that the rule works
	reqCtx := &plugins.RequestContext{
		IP:          "192.168.1.6",
		UserAgent:   "Mozilla/5.0",
		Method:      "GET",
		Path:        "/test",
		Headers:     make(map[string]string),
		QueryParams: make(map[string]string),
	}

	result := detector.Detect(context.Background(), reqCtx)

	if !result.Threat {
		t.Error("Expected test rule to trigger")
	}

	// Test updating the rule
	rule.Severity = 7
	err = detector.UpdateRule("test_rule", rule)
	if err != nil {
		t.Fatalf("Failed to update rule: %v", err)
	}

	result = detector.Detect(context.Background(), reqCtx)
	if result.Severity != 7 {
		t.Errorf("Expected updated severity 7, got %d", result.Severity)
	}

	// Test disabling the rule
	err = detector.EnableRule("test_rule", false)
	if err != nil {
		t.Fatalf("Failed to disable rule: %v", err)
	}

	result = detector.Detect(context.Background(), reqCtx)
	if result.Threat {
		t.Error("Expected disabled rule to not trigger")
	}

	// Test removing the rule
	err = detector.RemoveRule("test_rule")
	if err != nil {
		t.Fatalf("Failed to remove rule: %v", err)
	}

	// Verify rule is gone
	rules := detector.GetRules()
	if len(rules) != 0 {
		t.Errorf("Expected 0 rules after removal, got %d", len(rules))
	}
}

func TestGenericDetectorMetrics(t *testing.T) {
	detector := NewGenericDetector()

	config := map[string]any{
		"rules": []any{
			map[string]any{
				"id":          "test_metric_rule",
				"name":        "Test Metric Rule",
				"description": "Rule for testing metrics",
				"enabled":     true,
				"type":        "test",
				"severity":    5,
				"confidence":  0.8,
				"priority":    50,
				"conditions": []any{
					map[string]any{
						"field":    "path",
						"operator": "contains",
						"value":    "test",
					},
				},
				"actions": []any{"warning_action"},
				"tags":    []any{"test"},
			},
		},
	}

	err := detector.Initialize(config)
	if err != nil {
		t.Fatalf("Failed to initialize detector: %v", err)
	}

	// Make some test requests
	reqCtx1 := &plugins.RequestContext{
		Path: "/test/endpoint",
	}
	reqCtx2 := &plugins.RequestContext{
		Path: "/normal/endpoint",
	}

	// This should trigger the rule
	result1 := detector.Detect(context.Background(), reqCtx1)
	if !result1.Threat {
		t.Error("Expected first request to trigger rule")
	}

	// This should not trigger the rule
	result2 := detector.Detect(context.Background(), reqCtx2)
	if result2.Threat {
		t.Error("Expected second request to not trigger rule")
	}

	// Check metrics
	metrics := detector.GetMetrics()

	if totalChecks, ok := metrics["total_checks"].(int64); !ok || totalChecks != 2 {
		t.Errorf("Expected total_checks to be 2, got %v", metrics["total_checks"])
	}

	if threatsFound, ok := metrics["threats_found"].(int64); !ok || threatsFound != 1 {
		t.Errorf("Expected threats_found to be 1, got %v", metrics["threats_found"])
	}

	if rulesCount, ok := metrics["rules_count"].(int); !ok || rulesCount != 1 {
		t.Errorf("Expected rules_count to be 1, got %v", metrics["rules_count"])
	}
}
