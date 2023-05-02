package scanner

import (
	"context"
	"fmt"
	"math/rand"
	"net"
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
	urlsList []string,
	port []string,
	ipv4 bool,
	ipv6 bool,
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
		urls:     urls,
		port:     port,
		ipv4:     ipv4,
		ipv6:     ipv6,
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
			fingerprint := el.Fingerprint
			var addr string
			if t.ipv4 {
				for _, ad := range el.OrAddresses {
					if ad[0] != '[' {
						addr = ad
					}
				}
			} else if t.ipv6 {
				for _, ad := range el.OrAddresses {
					if ad[0] == '[' {
						addr = ad
					}
				}
			} else {
				addr = el.OrAddresses[r.Intn(len(el.OrAddresses))]
			}
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

// GetRelays returns available relays in json format
func (t *torRelayScanner) GetRelays() ([]byte, error) {
	t.loadRelays()

	mu := sync.Mutex{}
	var relays Relays
	sem := make(chan struct{}, 30)
	for _, el := range t.relayInfo.Relays {
		el := el
		sem <- struct{}{}
		go func() {
			if tcpSocketConnectChecker(el.OrAddresses[0], t.timeout) {
				mu.Lock()
				relays = append(relays, Relay{
					Fingerprint: el.Fingerprint,
					OrAddresses: el.OrAddresses,
				})
				mu.Unlock()
			}
			<-sem
		}()
	}
	if len(relays) == 0 {
		fmt.Fprintf(os.Stderr, "No relays are reachable this try.\n\n")
		return nil, fmt.Errorf("no relays are reachable this try")
	}

	result, err := json.MarshalIndent(RelayInfo{
		Version:          t.relayInfo.Version,
		BuildRevision:    t.relayInfo.BuildRevision,
		RelaysPublished:  t.relayInfo.RelaysPublished,
		Relays:           relays,
		BridgesPublished: t.relayInfo.BridgesPublished,
		Bridges:          Bridges{},
	}, "", " ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot marshal RelayInfo: %v.\n", err)
		return nil, err
	}

	return result, nil
}

func (t *torRelayScanner) loadRelays() {
	fmt.Printf("Tor Relay Scanner. Will scan up to %d working relays (or till the end)\n", t.goal)
	fmt.Println("Downloading Tor Relay information from Tor Metrics...")
	fmt.Println()

	var (
		err error
	)

	for _, addr := range t.urls {
		t.relays, t.relayInfo, err = t.grab(addr)
		if err != nil {
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

func (t *torRelayScanner) grab(addr string) (Relays, RelayInfo, error) {
	var relayInfo RelayInfo
	u, _ := url.Parse(addr)
	err := requests.
		URL(addr).
		UserAgent("tor-relay-scanner").
		ToJSON(&relayInfo).
		Fetch(context.Background())
	if err != nil {
		fmt.Printf("Can't download Tor Relay data from/via %s: %v\n\n", u.Hostname(), err)
		return nil, RelayInfo{}, err
	}

	fmt.Printf("Download from %s\n\n", u.Hostname())
	return relayInfo.Relays, relayInfo, nil
}

// tcpSocketConnectChecker just checked network connection with specific host:port
func tcpSocketConnectChecker(addr string, timeout time.Duration) bool {
	_, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	return true
}
