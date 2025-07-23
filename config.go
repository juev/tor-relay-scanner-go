package scanner

import (
	"errors"
	"time"
)

// Constants for configuration defaults and limits
const (
	// MinTimeout is the minimum allowed connection timeout
	MinTimeout = 50 * time.Millisecond
	
	// DefaultTimeout is the default connection timeout
	DefaultTimeout = 200 * time.Millisecond
	
	// DefaultDeadline is the default program execution deadline
	DefaultDeadline = 1 * time.Minute
	
	// DefaultPoolSize is the default number of concurrent relays tested
	DefaultPoolSize = 100
	
	// DefaultGoal is the default number of working relays to find
	DefaultGoal = 5
	
	// HTTPRequestTimeout is the timeout for HTTP requests to fetch relay data
	HTTPRequestTimeout = 30 * time.Second
)

// Config holds all configuration for the Tor relay scanner
type Config struct {
	// PoolSize is the number of concurrent relays tested
	PoolSize int
	
	// Goal is the number of working relays to find
	Goal int
	
	// Timeout is the socket connection timeout
	Timeout time.Duration
	
	// Deadline is the maximum execution time for the program
	Deadline time.Duration
	
	// URLs are the sources for relay information
	URLs []string
	
	// Ports to scan (if empty, all ports are scanned)
	Ports []string
	
	// ExcludePorts to skip during scanning
	ExcludePorts []string
	
	// IPv4 only mode
	IPv4 bool
	
	// IPv6 only mode
	IPv6 bool
	
	// Silent mode (no progress output)
	Silent bool
	
	// PreferredCountry is a comma-separated list of country codes
	PreferredCountry string
	
	// OutputFile is the path to write results
	OutputFile string
	
	// TorRC format output
	TorRC bool
	
	// JSON format output
	JSONOutput bool
}

// NewDefaultConfig returns a Config with default values
func NewDefaultConfig() *Config {
	return &Config{
		PoolSize: DefaultPoolSize,
		Goal:     DefaultGoal,
		Timeout:  DefaultTimeout,
		Deadline: DefaultDeadline,
		URLs:     []string{},
		Ports:    []string{},
		ExcludePorts: []string{},
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Timeout < MinTimeout {
		return errors.New("timeout must be at least 50ms")
	}
	
	if c.Timeout > c.Deadline {
		return errors.New("deadline must be greater than timeout")
	}
	
	if c.PoolSize <= 0 {
		return errors.New("pool size must be positive")
	}
	
	if c.Goal <= 0 {
		return errors.New("goal must be positive")
	}
	
	return nil
}