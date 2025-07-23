package scanner

import (
	"context"
	"time"
)

// TorRelayScanner defines the interface for scanning Tor relays.
// It provides methods to retrieve available Tor relays in different formats.
type TorRelayScanner interface {
	Grab() (relays []ResultRelay)
	GetJSON() []byte
	WithContext(ctx context.Context) TorRelayScanner
}

type torRelayScanner struct {
	relayInfo RelayInfo
	// The number of concurrent relays tested. default=30
	poolSize int
	// Test until at least this number of working relays are found. default=5
	goal int
	// Socket connection timeout. default=1s
	timeout time.Duration
	// Preferred alternative URL for onionoo relay list. Could be used multiple times
	urls []string
	// Scan for relays running on specified port number. Could be used multiple times
	ports []string
	// Exclude relays running on specified port number. Could be used multiple times
	excludePorts []string
	// Use ipv4 only nodes
	ipv4 bool
	// Use ipv6 only nodes
	ipv6 bool
	// Silent mode
	silent bool
	// Deadline time
	deadline time.Duration
	// Preferred country list, comma-separated. Example: se,gb,nl,det
	country string
	// Logger for output
	logger *Logger
	// Context for cancellation
	ctx context.Context
}

type (
	version          string
	buildRevision    string
	relaysPublished  string
	bridgesPublished string
	bridges          []any
)

// RelayInfo struct with basics information relay lists
type RelayInfo struct {
	Version          version
	BuildRevision    buildRevision    `json:"build_revision"`
	RelaysPublished  relaysPublished  `json:"relays_published"`
	Relays           Relays           `json:"relays"`
	BridgesPublished bridgesPublished `json:"bridges_published"`
	Bridges          bridges          `json:"bridges"`
}

// Relays represents a slice of Relay structs
type Relays []Relay

// Relay represents a single Tor relay with its network information
type Relay struct {
	Fingerprint string   `json:"fingerprint"`
	OrAddresses []string `json:"or_addresses"`
	Country     string   `json:"country"`
}

// ResultRelay represents a Tor relay result with a selected address
type ResultRelay struct {
	Fingerprint string `json:"fingerprint"`
	Address     string `json:"or_addresses"`
}
