package scanner

import (
	"time"
)

// TorRelayScanner ...
type TorRelayScanner interface {
	Grab() (relays []ResultRelay)
}

type torRelayScanner struct {
	relays Relays
	// The number of concurrent relays tested. default=30
	poolSize int
	// Test until at least this number of working relays are found. default=5
	goal int
	// Socket connection timeout. default=1s
	timeout time.Duration
	// Output reachable relays to file. default=sys.stdout
	outfile string
	// Set proxy for onionoo information download. Format: http://user:pass@host:port; socks5h://user:pass@host:port
	proxy string
	// Preferred alternative URL for onionoo relay list. Could be used multiple times
	urls []string
	// Scan for relays running on specified port number. Could be used multiple times
	port []string
	// Use ipv4 only nodes
	ipv4 bool
}

// RelayInfo struct with basics information relay lists
type RelayInfo struct {
	Version         string
	BuildRevision   string `json:"build_revision"`
	RelaysPublished string `json:"relays_published"`
	Relays          Relays `json:"relays"`
}

// Relays ...
type Relays []Relay

// Relay ...
type Relay struct {
	Fingerprint string   `json:"fingerprint"`
	OrAddresses []string `json:"or_addresses"`
}

// ResultRelay ...
type ResultRelay struct {
	Fingerprint string `json:"fingerprint"`
	Addresses   string `json:"or_addresses"`
}
