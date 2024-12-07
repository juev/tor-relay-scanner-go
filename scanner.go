package scanner

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
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
	excludePorts []string,
	ipv4 bool,
	ipv6 bool,
	silent bool,
	deadline time.Duration,
	country string,
) TorRelayScanner {
	baseURL := "https://onionoo.torproject.org/details?type=relay&running=true&fields=fingerprint,or_addresses,country"

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
		poolSize:     poolSize,
		goal:         goal,
		timeout:      timeout,
		urls:         urls,
		ports:        port,
		excludePorts: excludePorts,
		ipv4:         ipv4,
		ipv6:         ipv6,
		silent:       silent,
		deadline:     deadline,
		country:      country,
	}
}

// Grab returns relay list from public addresses
func (t *torRelayScanner) Grab() (relays []ResultRelay) {
	resultRelays := t.getRelays()
	if len(resultRelays) == 0 {
		return nil
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for _, el := range resultRelays {
		if len(el.OrAddresses) > 0 {
			relays = append(relays, ResultRelay{
				Fingerprint: el.Fingerprint,
				Address:     el.OrAddresses[r.Intn(len(el.OrAddresses))],
			})
		}
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
	go t.testRelays(chanRelays)

	bar := t.createProgressBar()

	var relays Relays
loop:
	for i := 1; i <= t.goal; i++ {
		select {
		case el, opened := <-chanRelays:
			if !opened {
				break loop
			}
			relays = append(relays, el)
			_ = bar.Add(1)
		case <-time.After(t.deadline):
			_ = bar.Add(t.goal)
			color.Fprintf(os.Stderr, "\nThe program was running for more than the specified time: %.2fs\n", t.deadline.Seconds())
			break loop
		}
	}

	return relays
}

func (t *torRelayScanner) testRelays(chanRelays chan Relay) {
	p := pool.New().WithMaxGoroutines(t.poolSize)
	for _, el := range t.relayInfo.Relays {
		el := el
		p.Go(func() {
			if tcpSocketConnectChecker(el.OrAddresses[0], t.timeout) {
				chanRelays <- Relay{
					Fingerprint: el.Fingerprint,
					OrAddresses: el.OrAddresses,
					Country:     el.Country,
				}
			}
		})
	}
	p.Wait()
	close(chanRelays)
}

func (t *torRelayScanner) createProgressBar() *progressbar.ProgressBar {
	return progressbar.NewOptions(
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
}

func (t *torRelayScanner) loadRelays() error {
	for _, addr := range t.urls {
		var err error
		t.relayInfo, err = t.grab(addr)
		if err == nil {
			break
		}
	}

	if len(t.relayInfo.Relays) == 0 {
		return errors.New("tor Relay information can't be downloaded")
	}

	t.relayInfo.Relays = t.filterRelays(t.relayInfo.Relays)

	if len(t.relayInfo.Relays) == 0 {
		return errors.New("there are no relays within specified port number constrains!\nTry changing port numbers")
	}

	shuffle(t.relayInfo.Relays)
	return nil
}

// filterRelays filters relays by country and addresses
func (t *torRelayScanner) filterRelays(relays Relays) Relays {
	var filtered Relays
	for _, rel := range relays {
		if !t.filterCountry(rel) {
			continue
		}

		orAddresses := t.filterAddresses(rel.OrAddresses)
		if len(orAddresses) > 0 {
			rel.OrAddresses = orAddresses
			filtered = append(filtered, rel)
		}
	}
	return filtered
}

// filterCountry filters relays by country
// if country is empty, it returns false
// if relay's country is in the list of countries, it returns true
func (t *torRelayScanner) filterCountry(relay Relay) bool {
	if t.country == "" {
		return true
	}

	return slices.Contains(strings.Split(t.country, ","), relay.Country)
}

func (t *torRelayScanner) filterAddresses(addresses []string) []string {
	var filtered []string
	for _, addr := range addresses {
		if t.skipAddrType(addr) || t.skipPorts(addr) {
			continue
		}
		filtered = append(filtered, addr)
	}
	return filtered
}

func (t *torRelayScanner) skipPorts(addr string) bool {
	u, _ := url.Parse("//" + addr)
	var skip bool
	if len(t.ports) > 0 {
		if !slices.Contains(t.ports, u.Port()) {
			skip = true
		}
	}
	if len(t.excludePorts) > 0 {
		if slices.Contains(t.excludePorts, u.Port()) {
			skip = true
		}
	}

	return skip
}

func (t *torRelayScanner) skipAddrType(addr string) bool {
	if t.ipv4 && !t.ipv6 {
		return addr[0] == '['
	}
	if t.ipv6 && !t.ipv4 {
		return addr[0] != '['
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
