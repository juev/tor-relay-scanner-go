package main

var (
	poolSize int
	// Test until at least this number of working relays are found. default=5
	goal int
	// Socket connection timeout. default=1s
	timeout int
	// Output reachable relays to file. default=sys.stdout
	outfile string
	// Output reachable relays in torrc format (with "Bridge" prefix)
	torrc bool
	// Preferred alternative URL for onionoo relay list. Could be used multiple times
	urls []string
	// Scan for relays running on specified port number. Could be used multiple times
	port []string
	// Use ipv4 only nodes
	ipv4 bool
	// Use ipv6 only nodes
	ipv6 bool
	// Get available relays in json format
	jsonRelays bool
	// Silent mode
	silent bool
)
