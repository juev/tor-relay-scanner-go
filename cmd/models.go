package main

const Description = "Downloads all Tor Relay IP addresses from onionoo.torproject.org and checks whether random Relays are available."

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
	// Set proxy for onionoo information download. Format: http://user:pass@host:port; socks5h://user:pass@host:port
	proxy string
	// Preferred alternative URL for onionoo relay list. Could be used multiple times
	urls []string
	// Scan for relays running on specified port number. Could be used multiple times
	port []string
)
