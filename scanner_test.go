package scanner

import (
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name         string
		poolSize     int
		goal         int
		timeout      time.Duration
		expectedURLs int
	}{
		{
			name:         "default configuration",
			poolSize:     100,
			goal:         5,
			timeout:      200 * time.Millisecond,
			expectedURLs: 4, // Base URLs
		},
		{
			name:         "with custom URLs",
			poolSize:     50,
			goal:         10,
			timeout:      500 * time.Millisecond,
			expectedURLs: 6, // 2 custom + 4 base
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var urls []string
			if tt.expectedURLs > 4 {
				urls = []string{"http://custom1.com", "http://custom2.com"}
			}

			cfg := &Config{
				PoolSize: tt.poolSize,
				Goal:     tt.goal,
				Timeout:  tt.timeout,
				URLs:     urls,
				Deadline: 1 * time.Minute,
			}
			scanner := New(cfg)

			ts, ok := scanner.(*torRelayScanner)
			if !ok {
				t.Fatal("expected *torRelayScanner type")
			}

			if ts.poolSize != tt.poolSize {
				t.Errorf("poolSize = %d, want %d", ts.poolSize, tt.poolSize)
			}

			if ts.goal != tt.goal {
				t.Errorf("goal = %d, want %d", ts.goal, tt.goal)
			}

			if ts.timeout != tt.timeout {
				t.Errorf("timeout = %v, want %v", ts.timeout, tt.timeout)
			}

			if len(ts.urls) != tt.expectedURLs {
				t.Errorf("urls count = %d, want %d", len(ts.urls), tt.expectedURLs)
			}
		})
	}
}

func TestFilterCountry(t *testing.T) {
	tests := []struct {
		name           string
		country        string
		relayCountry   string
		expectedResult bool
	}{
		{
			name:           "empty filter accepts all",
			country:        "",
			relayCountry:   "us",
			expectedResult: true,
		},
		{
			name:           "single country match",
			country:        "us",
			relayCountry:   "us",
			expectedResult: true,
		},
		{
			name:           "single country no match",
			country:        "us",
			relayCountry:   "de",
			expectedResult: false,
		},
		{
			name:           "multiple countries match",
			country:        "us,de,fr",
			relayCountry:   "de",
			expectedResult: true,
		},
		{
			name:           "multiple countries no match",
			country:        "us,de,fr",
			relayCountry:   "ru",
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := &torRelayScanner{
				country: tt.country,
			}
			relay := Relay{
				Country: tt.relayCountry,
			}

			result := scanner.filterCountry(relay)
			if result != tt.expectedResult {
				t.Errorf("filterCountry() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

func TestSkipAddrType(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		ipv4     bool
		ipv6     bool
		expected bool
	}{
		{
			name:     "ipv4 address with ipv4 only",
			addr:     "192.168.1.1:9001",
			ipv4:     true,
			ipv6:     false,
			expected: false,
		},
		{
			name:     "ipv6 address with ipv4 only",
			addr:     "[2001:db8::1]:9001",
			ipv4:     true,
			ipv6:     false,
			expected: true,
		},
		{
			name:     "ipv4 address with ipv6 only",
			addr:     "192.168.1.1:9001",
			ipv4:     false,
			ipv6:     true,
			expected: true,
		},
		{
			name:     "ipv6 address with ipv6 only",
			addr:     "[2001:db8::1]:9001",
			ipv4:     false,
			ipv6:     true,
			expected: false,
		},
		{
			name:     "both protocols enabled",
			addr:     "192.168.1.1:9001",
			ipv4:     true,
			ipv6:     true,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := &torRelayScanner{
				ipv4: tt.ipv4,
				ipv6: tt.ipv6,
			}

			result := scanner.skipAddrType(tt.addr)
			if result != tt.expected {
				t.Errorf("skipAddrType(%s) = %v, want %v", tt.addr, result, tt.expected)
			}
		})
	}
}

func TestSkipPorts(t *testing.T) {
	tests := []struct {
		name         string
		addr         string
		ports        []string
		excludePorts []string
		expected     bool
	}{
		{
			name:     "no port filters",
			addr:     "192.168.1.1:9001",
			expected: false,
		},
		{
			name:     "port in allowed list",
			addr:     "192.168.1.1:9001",
			ports:    []string{"9001", "443"},
			expected: false,
		},
		{
			name:     "port not in allowed list",
			addr:     "192.168.1.1:9001",
			ports:    []string{"443", "80"},
			expected: true,
		},
		{
			name:         "port in exclude list",
			addr:         "192.168.1.1:9001",
			excludePorts: []string{"9001", "9030"},
			expected:     true,
		},
		{
			name:         "port not in exclude list",
			addr:         "192.168.1.1:9001",
			excludePorts: []string{"443", "80"},
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := &torRelayScanner{
				ports:        tt.ports,
				excludePorts: tt.excludePorts,
			}

			result := scanner.skipPorts(tt.addr)
			if result != tt.expected {
				t.Errorf("skipPorts(%s) = %v, want %v", tt.addr, result, tt.expected)
			}
		})
	}
}

func TestFilterAddresses(t *testing.T) {
	scanner := &torRelayScanner{
		ipv4:         true,
		ipv6:         false,
		ports:        []string{"9001"},
		excludePorts: []string{"9030"},
	}

	addresses := []string{
		"192.168.1.1:9001",   // Should pass
		"[2001:db8::1]:9001", // Should fail (ipv6)
		"192.168.1.2:9030",   // Should fail (excluded port)
		"192.168.1.3:443",    // Should fail (not in allowed ports)
		"10.0.0.1:9001",      // Should pass
	}

	filtered := scanner.filterAddresses(addresses)

	if len(filtered) != 2 {
		t.Errorf("Expected 2 addresses, got %d", len(filtered))
	}

	expected := []string{"192.168.1.1:9001", "10.0.0.1:9001"}
	for i, addr := range filtered {
		if addr != expected[i] {
			t.Errorf("filtered[%d] = %s, want %s", i, addr, expected[i])
		}
	}
}

func TestTcpSocketConnectChecker(t *testing.T) {
	// Test with invalid address (should fail quickly)
	result := tcpSocketConnectChecker("invalid:address:format", 100*time.Millisecond)
	if result {
		t.Error("Expected false for invalid address format")
	}

	// Test with unreachable address
	result = tcpSocketConnectChecker("192.0.2.1:9999", 100*time.Millisecond)
	if result {
		t.Error("Expected false for unreachable address")
	}
}
