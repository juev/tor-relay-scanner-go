package main

import (
	"io"
	"os"
	"time"

	"github.com/gookit/color"
	flag "github.com/spf13/pflag"

	scanner "github.com/juev/tor-relay-scanner-go"
)

var torRc, jsonRelays, silent bool
var outfile string

func main() {
	sc := create()

	var prefix string
	if torRc {
		prefix = "Bridge "
	}

	var writer io.Writer
	writer = os.Stdout
	if silent && outfile != "" {
		writer = io.Discard
	}
	out := io.MultiWriter(writer)

	if outfile != "" {
		logFile, err := os.OpenFile(outfile, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0666)
		if err != nil {
			color.Fprintf(os.Stderr, "cannot create file (%s): %s\n", outfile, err.Error())
			os.Exit(2)
		}
		out = io.MultiWriter(writer, logFile)
	}

	if jsonRelays {
		relays := sc.GetJSON()
		color.Fprintf(out, "%s\n", relays)
		return
	}

	relays := sc.Grab()
	if len(relays) == 0 {
		color.Fprintf(os.Stderr, "No relays are reachable this try.\n")
		os.Exit(3)
	}

	for _, el := range relays {
		color.Fprintf(out, "%s%s %s\n", prefix, el.Address, el.Fingerprint)
	}
	if torRc {
		color.Fprintf(out, "UseBridges 1\n")
	}
}

func usage() {
	color.Fprintln(os.Stdout, "Usage of tor-relay-scanner-go:")
	flag.PrintDefaults()
	os.Exit(0)
}

func create() scanner.TorRelayScanner {
	var poolSize, goal int
	var timeoutStr, deadlineStr string
	var urls, port []string
	var ipv4, ipv6 bool

	flag.IntVarP(&poolSize, "num_relays", "n", 100, `The number of concurrent relays tested.`)
	flag.IntVarP(&goal, "working_relay_num_goal", "g", 5, `Test until at least this number of working relays are found`)
	flag.StringVarP(&timeoutStr, "timeout", "t", "200ms", `Socket connection timeout`)
	flag.StringVarP(&outfile, "outfile", "o", "", `Output reachable relays to file`)
	flag.BoolVar(&torRc, "torrc", false, `Output reachable relays in torrc format (with "Bridge" prefix)`)
	flag.StringArrayVarP(&urls, "url", "u", []string{}, `Preferred alternative URL for onionoo relay list. Could be used multiple times.`)
	flag.StringArrayVarP(&port, "port", "p", []string{}, `Scan for relays running on specified port number. Could be used multiple times.`)
	flag.BoolVarP(&ipv4, "ipv4", "4", false, `Use ipv4 only nodes`)
	flag.BoolVarP(&ipv6, "ipv6", "6", false, `Use ipv6 only nodes`)
	flag.BoolVarP(&jsonRelays, "json", "j", false, `Get available relays in json format`)
	flag.BoolVarP(&silent, "silent", "s", false, `Silent mode`)
	flag.StringVarP(&deadlineStr, "deadline", "d", "1m", `The deadline of program execution`)

	flag.Usage = usage
	flag.Parse()

	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		color.Printf("cannot parse timeout duration: %s\n", err)
		os.Exit(1)
	}

	if timeout < 50*time.Millisecond {
		color.Println("It doesn't make sense to set a timeout of less than 50 ms")
		os.Exit(1)
	}

	deadline, err := time.ParseDuration(deadlineStr)
	if err != nil {
		color.Printf("cannot parse deadline duration: %s\n", err)
		os.Exit(1)
	}

	if timeout > deadline {
		color.Println("The deadline must be greater than the timeout")
		os.Exit(1)
	}

	sc := scanner.New(
		poolSize,
		goal,
		timeout,
		urls,
		port,
		ipv4,
		ipv6,
		silent,
		deadline,
	)

	return sc
}
