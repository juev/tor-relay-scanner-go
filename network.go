package scanner

import (
	"context"
	"net"
	"time"

	"github.com/carlmjohnson/requests"
)

// grab fetches relay information from the given URL
func (t *torRelayScanner) grab(addr string) (RelayInfo, error) {
	var relayInfo RelayInfo
	
	// Create context with timeout for HTTP request
	ctx, cancel := context.WithTimeout(context.Background(), HTTPRequestTimeout)
	defer cancel()
	
	err := requests.
		URL(addr).
		UserAgent("tor-relay-scanner").
		ToJSON(&relayInfo).
		Fetch(ctx)
	if err != nil {
		return RelayInfo{}, err
	}

	return relayInfo, nil
}

// tcpSocketConnectChecker checks network connection with specific host:port
func tcpSocketConnectChecker(addr string, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()

	return true
}