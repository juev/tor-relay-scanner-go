package main

import (
	"context"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gookit/color"
	flag "github.com/spf13/pflag"

	scanner "github.com/juev/tor-relay-scanner-go"
)

var (
	torRc, jsonRelays, silent bool
	outfile                   string
	ipv6                      bool
)

func main() {
	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\nReceived interrupt signal, shutting down gracefully...")
		cancel()
	}()

	sc := createScanner().WithContext(ctx)

	writer := setupOutputWriter()
	out := io.MultiWriter(writer)

	// Check if context was cancelled
	select {
	case <-ctx.Done():
		log.Println("Shutdown requested before operation started")
		return
	default:
	}

	if jsonRelays {
		printJSONRelays(sc, out)
		return
	}

	printRelays(sc, out)
}

func setupOutputWriter() io.Writer {
	var writer io.Writer = os.Stdout
	if silent && outfile != "" {
		writer = io.Discard
	}
	if outfile != "" {
		logFile, err := os.OpenFile(outfile, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0666)
		if err != nil {
			log.Fatalf("cannot create file (%s): %s\n", outfile, err.Error())
		}
		writer = io.MultiWriter(writer, logFile)
	}
	return writer
}

func printJSONRelays(sc scanner.TorRelayScanner, out io.Writer) {
	relays := sc.GetJSON()
	color.Fprintf(out, "%s\n", relays)
}

func printRelays(sc scanner.TorRelayScanner, out io.Writer) {
	relays := sc.Grab()
	if len(relays) == 0 {
		log.Fatal("No relays are reachable this try.")
	}

	var prefix string
	if torRc {
		prefix = "Bridge "
	}

	for _, el := range relays {
		color.Fprintf(out, "%s%s %s\n", prefix, el.Address, el.Fingerprint)
	}
	if torRc {
		color.Fprintf(out, "UseBridges 1\n")
		if ipv6 {
			color.Fprintf(out, "ClientPreferIPv6ORPort 1\n")
		}
	}
}

func usage() {
	color.Fprintln(os.Stdout, "Usage of tor-relay-scanner-go:")
	flag.PrintDefaults()
	os.Exit(0)
}

func createScanner() scanner.TorRelayScanner {
	cfg := scanner.NewDefaultConfig()
	var timeoutStr, deadlineStr string

	flag.IntVarP(&cfg.PoolSize, "num_relays", "n", scanner.DefaultPoolSize, `The number of concurrent relays tested.`)
	flag.IntVarP(&cfg.Goal, "working_relay_num_goal", "g", scanner.DefaultGoal, `Test until at least this number of working relays are found`)
	flag.StringVarP(&timeoutStr, "timeout", "t", "200ms", `Socket connection timeout`)
	flag.StringVarP(&outfile, "outfile", "o", "", `Output reachable relays to file`)
	flag.BoolVar(&torRc, "torrc", false, `Output reachable relays in torrc format (with "Bridge" prefix)`)
	flag.StringArrayVarP(&cfg.URLs, "url", "u", []string{}, `Preferred alternative URL for onionoo relay list. Could be used multiple times.`)
	flag.StringArrayVarP(&cfg.Ports, "port", "p", []string{}, `Scan for relays running on specified port number. Could be used multiple times.`)
	flag.StringArrayVarP(&cfg.ExcludePorts, "exclude_port", "x", []string{}, `Scan relays with exception of certain port number. Could be used multiple times.`)
	flag.BoolVarP(&cfg.IPv4, "ipv4", "4", false, `Use ipv4 only nodes`)
	flag.BoolVarP(&ipv6, "ipv6", "6", false, `Use ipv6 only nodes`)
	flag.BoolVarP(&jsonRelays, "json", "j", false, `Get available relays in json format`)
	flag.BoolVarP(&silent, "silent", "s", false, `Silent mode`)
	flag.StringVarP(&deadlineStr, "deadline", "d", "1m", `The deadline of program execution`)
	flag.StringVarP(&cfg.PreferredCountry, "preferred-country", "c", "", `Preferred country list, comma-separated. Example: se,gb,nl,det`)

	flag.Usage = usage
	flag.Parse()

	cfg.Timeout = parseDuration(timeoutStr)
	cfg.Deadline = parseDuration(deadlineStr)
	cfg.OutputFile = outfile
	cfg.TorRC = torRc
	cfg.JSONOutput = jsonRelays
	cfg.Silent = silent
	cfg.IPv6 = ipv6

	if err := cfg.Validate(); err != nil {
		color.Printf("Configuration error: %s\n", err)
		os.Exit(1)
	}

	return scanner.New(cfg)
}

func parseDuration(durationStr string) time.Duration {
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		color.Printf("cannot parse duration: %s\n", err)
		os.Exit(1)
	}
	return duration
}
