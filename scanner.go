package scanner

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/carlmjohnson/requests"

	json "github.com/json-iterator/go"
)

// New ...
func New(
	poolSize int,
	goal int,
	timeout time.Duration,
	outfile string,
	proxy string,
	urlsList []string,
	port []string,
	ipv4 bool,
) TorRelayScanner {
	baseURL := "https://onionoo.torproject.org/details?type=relay&running=true&fields=fingerprint,or_addresses"

	// Use public CORS proxy as a regular proxy in case if onionoo.torproject.org is unreachable
	urls := []string{
		baseURL,
		"https://icors.vercel.app/?" + url.QueryEscape(baseURL),
		"https://github.com/ValdikSS/tor-onionoo-mirror/raw/master/details-running-relays-fingerprint-address-only.json",
		"https://bitbucket.org/ValdikSS/tor-onionoo-mirror/raw/master/details-running-relays-fingerprint-address-only.json",
	}

	// Additional urls should be first
	if len(urlsList) > 0 {
		urls = append(urlsList, urls...)
	}

	return &torRelayScanner{
		relays:   Relays{},
		poolSize: poolSize,
		goal:     goal,
		timeout:  timeout,
		outfile:  outfile,
		proxy:    proxy,
		urls:     urls,
		port:     port,
		ipv4:     ipv4,
	}
}

// Grab returns relay list from public addresses
func (t *torRelayScanner) Grab() (relays []ResultRelay) {
	t.loadRelays()

	fmt.Printf("Test started...\n\n")

	numTries := len(t.relays) / t.poolSize
	relayPos := 0

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 1; i <= numTries; i++ {
		if len(relays) >= t.goal {
			break
		}

		fmt.Printf("Try %d/%d, We'll test the following %d random relays:\n", i, numTries, t.poolSize)

		relayNum := min(t.poolSize, len(t.relays)-relayPos-1)
		for _, el := range t.relays[relayPos : relayPos+relayNum] {
			p, _ := json.Marshal(el)
			fmt.Printf("%s\n", p)
		}
		fmt.Println()

		mu := sync.Mutex{}
		wg := sync.WaitGroup{}
		var testRelays []ResultRelay
		for _, el := range t.relays[relayPos : relayPos+relayNum] {
			index := r.Intn(len(el.OrAddresses))
			if t.ipv4 {
				index = 0
			}
			addr := el.OrAddresses[index]
			fingerprint := el.Fingerprint
			wg.Add(1)
			go func() {
				defer wg.Done()
				if tcpSocketConnectChecker(addr, t.timeout) {
					mu.Lock()
					testRelays = append(testRelays, ResultRelay{
						Fingerprint: fingerprint,
						Addresses:   addr,
					})
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if len(testRelays) == 0 {
			fmt.Fprintf(os.Stderr, "No relays are reachable this try.\n\n")
		} else {
			fmt.Printf("The following relays are reachable this try:\n")
			for _, rel := range testRelays {
				p, _ := json.Marshal(rel)
				fmt.Printf("%s\n", p)
			}
			fmt.Println()
		}
		relays = append(relays, testRelays...)
		relayPos += t.poolSize
	}

	return relays[:t.goal]
}

func (t *torRelayScanner) loadRelays() {
	fmt.Printf("Tor Relay Scanner. Will scan up to %d working relays (or till the end)\n", t.goal)
	fmt.Println("Downloading Tor Relay information from Tor Metrics...")

	var (
		err error
	)

	for _, addr := range t.urls {
		t.relays, err = t.grab(addr, t.timeout)
		if err != nil {
			fmt.Printf("wtf: %v", err)
			continue
		}
		break
	}

	if t.relays == nil {
		fmt.Fprintln(os.Stderr, "Tor Relay information can't be downloaded!")
		os.Exit(1)
	}

	if len(t.port) > 0 {
		var tmp Relays
		for _, rel := range t.relays {
			addr := rel.OrAddresses[0]
			u, _ := url.Parse("//" + addr)
			for _, p := range t.port {
				if u.Port() == p {
					tmp = append(tmp, rel)
				}
			}
		}
		if len(tmp) == 0 {
			fmt.Fprintf(os.Stderr, "There are no relays within specified port number constrains!\n")
			fmt.Fprintf(os.Stderr, "Try changing port numbers.")
			os.Exit(2)
		}
		t.relays = tmp
	}

	shuffle(t.relays)

	fmt.Printf("Done!\n\n")
}

func (t *torRelayScanner) grab(addr string, timeout time.Duration) (Relays, error) {
	client := &http.Client{
		Timeout: timeout,
	}

	var transport http.Transport
	if t.proxy != "" {
		proxyURL, err := url.Parse(t.proxy)
		if err != nil {
			fmt.Printf("wtf: %v", err)
			return nil, fmt.Errorf("cannot parse proxy url")
		}
		transport = http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}

	var relayInfo RelayInfo
	err := requests.
		URL(addr).
		Client(client).
		Transport(&transport).
		ToJSON(&relayInfo).
		Fetch(context.Background())
	if err != nil {
		u, _ := url.Parse(addr)
		fmt.Printf("Can't download Tor Relay data from/via %s: %v", u.Hostname(), err)
		return nil, err
	}

	return relayInfo.Relays, nil
}

// tcpSocketConnectChecker just checked network connection with specific host:port
func tcpSocketConnectChecker(addr string, timeout time.Duration) bool {
	_, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	return true
}
