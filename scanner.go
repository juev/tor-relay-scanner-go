package scanner

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/carlmjohnson/requests"
	"github.com/gookit/color"
	"github.com/k0kubun/go-ansi"
	"github.com/schollz/progressbar/v3"
	"github.com/sourcegraph/conc/pool"

	json "github.com/json-iterator/go"
)

// New ...
func New(
	poolSize int,
	goal int,
	timeout time.Duration,
	urlsList []string,
	port []string,
	ipv4 bool,
	ipv6 bool,
	silent bool,
	deadline time.Duration,
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
		poolSize: poolSize,
		goal:     goal,
		timeout:  timeout,
		urls:     urls,
		ports:    port,
		ipv4:     ipv4,
		ipv6:     ipv6,
		silent:   silent,
		deadline: deadline,
	}
}

// Grab returns relay list from public addresses
func (t *torRelayScanner) Grab() (relays []ResultRelay) {
	resultRelays := t.getRelays()
	if len(resultRelays) == 0 {
		return nil
	}

	for _, el := range resultRelays {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(el.OrAddresses))))
		relays = append(relays, ResultRelay{
			Fingerprint: el.Fingerprint,
			Address:     el.OrAddresses[n.Uint64()],
		})
	}

	return relays
}

// GetJSON returns available relays in json format
func (t *torRelayScanner) GetJSON() []byte {
	resultRelays := t.getRelays()
	if len(resultRelays) == 0 {
		return nil
	}

	result, _ := json.MarshalIndent(RelayInfo{
		Version:          t.relayInfo.Version,
		BuildRevision:    t.relayInfo.BuildRevision,
		RelaysPublished:  t.relayInfo.RelaysPublished,
		Relays:           resultRelays,
		BridgesPublished: t.relayInfo.BridgesPublished,
		Bridges:          bridges{},
	}, "", " ")

	return result
}

func (t *torRelayScanner) getRelays() Relays {
	if err := t.loadRelays(); err != nil {
		color.Fprintln(os.Stderr, "Tor Relay information can't be downloaded!")
		os.Exit(1)
	}

	chanRelays := make(chan Relay)
	go func() {
		p := pool.New().WithMaxGoroutines(t.poolSize)
		for _, el := range t.relayInfo.Relays {
			el := el
			p.Go(func() {
				if tcpSocketConnectChecker(el.OrAddresses[0], t.timeout) {
					chanRelays <- Relay{
						Fingerprint: el.Fingerprint,
						OrAddresses: el.OrAddresses,
					}
				}
			})
		}
		p.Wait()
	}()

	bar := progressbar.NewOptions(
		t.goal,
		progressbar.OptionSetDescription("Testing"),
		progressbar.OptionSetWidth(15),
		progressbar.OptionSetWriter(ansi.NewAnsiStdout()),
		progressbar.OptionShowCount(),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionSetVisibility(!t.silent),
	)

	var relays Relays
	for i := 0; i < t.goal; i++ {
		select {
		case el := <-chanRelays:
			relays = append(relays, el)
			_ = bar.Add(1)
		case <-time.After(t.deadline):
			_ = bar.Add(t.goal)
			color.Fprintf(os.Stderr, "\nThe program was running for more than the specified time: %.2fs\n", t.deadline.Seconds())
			goto loop
		}
	}

loop:
	return relays
}

func (t *torRelayScanner) loadRelays() (err error) {
	for _, addr := range t.urls {
		t.relayInfo, err = t.grab(addr)
		if err != nil {
			continue
		}
		break
	}

	if len(t.relayInfo.Relays) == 0 {
		return errors.New("tor Relay information can't be downloaded")
	}

	var filtered Relays
	for _, rel := range t.relayInfo.Relays {
		var orAddresses []string
		for _, addr := range rel.OrAddresses {
			if t.skipAddrType(addr) {
				continue
			}
			if t.checkPorts(addr) {
				continue
			}
			orAddresses = append(orAddresses, addr)
		}
		if len(orAddresses) > 0 {
			rel.OrAddresses = orAddresses
			filtered = append(filtered, rel)
		}
	}

	if len(filtered) == 0 {
		return errors.New("there are no relays within specified port number constrains!\nTry changing port numbers")
	}
	t.relayInfo.Relays = filtered

	shuffle(t.relayInfo.Relays)

	return nil
}

func (t *torRelayScanner) checkPorts(addr string) bool {
	if len(t.ports) > 0 {
		u, _ := url.Parse("//" + addr)
		var keep bool
		for _, p := range t.ports {
			if u.Port() == p {
				keep = true
			}
		}
		if !keep {
			return true
		}
	}
	return false
}

func (t *torRelayScanner) skipAddrType(addr string) bool {
	if t.ipv4 && !t.ipv6 {
		if addr[0] == '[' {
			return true
		}
	}
	if t.ipv6 && !t.ipv4 {
		if addr[0] != '[' {
			return true
		}
	}
	return false
}

func (t *torRelayScanner) grab(addr string) (RelayInfo, error) {
	var relayInfo RelayInfo
	err := requests.
		URL(addr).
		UserAgent("tor-relay-scanner").
		ToJSON(&relayInfo).
		Fetch(context.Background())
	if err != nil {
		return RelayInfo{}, err
	}

	return relayInfo, nil
}

// tcpSocketConnectChecker just checked network connection with specific host:port
func tcpSocketConnectChecker(addr string, timeout time.Duration) bool {
	d := net.Dialer{Deadline: time.Now().Add(timeout)}
	_, err := d.Dial("tcp", addr)

	return err == nil
}
