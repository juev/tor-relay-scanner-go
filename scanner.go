package scanner

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/k0kubun/go-ansi"
	"github.com/schollz/progressbar/v3"
	"github.com/sourcegraph/conc/pool"

	json "github.com/json-iterator/go"
)

// New creates a new TorRelayScanner with the provided configuration
func New(cfg *Config) TorRelayScanner {
	baseURL := "https://onionoo.torproject.org/details?type=relay&running=true&fields=fingerprint,or_addresses,country"

	// Use public CORS proxy as a regular proxy in case if onionoo.torproject.org is unreachable
	urls := []string{
		baseURL,
		"https://icors.vercel.app/?" + url.QueryEscape(baseURL),
		"https://github.com/ValdikSS/tor-onionoo-mirror/raw/master/details-running-relays-fingerprint-address-only.json",
		"https://bitbucket.org/ValdikSS/tor-onionoo-mirror/raw/master/details-running-relays-fingerprint-address-only.json",
	}

	// Additional urls should be first
	if len(cfg.URLs) > 0 {
		urls = append(cfg.URLs, urls...)
	}

	return &torRelayScanner{
		poolSize:     cfg.PoolSize,
		goal:         cfg.Goal,
		timeout:      cfg.Timeout,
		urls:         urls,
		ports:        cfg.Ports,
		excludePorts: cfg.ExcludePorts,
		ipv4:         cfg.IPv4,
		ipv6:         cfg.IPv6,
		silent:       cfg.Silent,
		deadline:     cfg.Deadline,
		country:      cfg.PreferredCountry,
		logger:       DefaultLogger(cfg.Silent),
		ctx:          context.Background(),
	}
}

// WithContext returns a new scanner with the provided context
func (t *torRelayScanner) WithContext(ctx context.Context) TorRelayScanner {
	newScanner := *t
	newScanner.ctx = ctx
	return &newScanner
}

// Grab returns relay list from public addresses
func (t *torRelayScanner) Grab() (relays []ResultRelay) {
	resultRelays := t.getRelays()
	if len(resultRelays) == 0 {
		return nil
	}

	for _, el := range resultRelays {
		if len(el.OrAddresses) > 0 {
			// Use crypto/rand for secure random selection
			idx, err := cryptoRandInt(len(el.OrAddresses))
			if err != nil {
				idx = 0 // Fallback to first address if crypto rand fails
			}
			relays = append(relays, ResultRelay{
				Fingerprint: el.Fingerprint,
				Address:     el.OrAddresses[idx],
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
		t.logger.Fatalf("Tor Relay information can't be downloaded: %v", err)
	}

	chanRelays := make(chan Relay)
	go t.testRelays(chanRelays)

	bar := t.createProgressBar()

	var relays Relays
	for i := 1; i <= t.goal; i++ {
		select {
		case <-t.ctx.Done():
			_ = bar.Add(t.goal)
			t.logger.Info("Scan cancelled by user")
			return relays
		case el, opened := <-chanRelays:
			if !opened {
				return relays
			}
			relays = append(relays, el)
			_ = bar.Add(1)
		case <-time.After(t.deadline):
			_ = bar.Add(t.goal)
			t.logger.Warn("The program was running for more than the specified time: %.2fs", t.deadline.Seconds())
			return relays
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
