package main

import (
	"io"
	"os"
	"time"

	"github.com/gookit/color"
	scanner "github.com/juev/tor-relay-scanner-go"
	flag "github.com/spf13/pflag"
)

func main() {
	usage := func() {
		color.Fprintln(os.Stdout, "Usage of tor-relay-scanner-go:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	flag.IntVarP(&poolSize, "num_relays", "n", 100, `The number of concurrent relays tested.`)
	flag.IntVarP(&goal, "working_relay_num_goal", "g", 5, `Test until at least this number of working relays are found`)
	flag.IntVarP(&timeout, "timeout", "t", 1, `Socket connection timeout`)
	flag.StringVarP(&outfile, "outfile", "o", "", `Output reachable relays to file`)
	flag.BoolVar(&torrc, "torrc", false, `Output reachable relays in torrc format (with "Bridge" prefix)`)
	flag.StringArrayVarP(&urls, "url", "u", []string{}, `Preferred alternative URL for onionoo relay list. Could be used multiple times.`)
	flag.StringArrayVarP(&port, "port", "p", []string{}, `Scan for relays running on specified port number. Could be used multiple times.`)
	flag.BoolVarP(&ipv4, "ipv4", "4", false, `Use ipv4 only nodes`)
	flag.BoolVarP(&ipv6, "ipv6", "6", false, `Use ipv6 only nodes`)
	flag.BoolVarP(&jsonRelays, "json", "j", false, `Get available relays in json format`)
	flag.Usage = usage
	flag.Parse()

	if timeout < 1 {
		timeout = 1
	}

	sc := scanner.New(
		poolSize,
		goal,
		time.Duration(timeout)*time.Second,
		outfile,
		urls,
		port,
		ipv4,
		ipv6,
	)

	var prefix string
	if torrc {
		prefix = "Bridge "
	}

	out := io.MultiWriter(os.Stdout)
	if outfile != "" {
		logFile, err := os.OpenFile(outfile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
		if err != nil {
			color.Fprintf(os.Stderr, "cannot create file (%s): %s", outfile, err.Error())
			os.Exit(3)
		}
		out = io.MultiWriter(os.Stdout, logFile)
	}

	if jsonRelays {
		relays := sc.GetJSON()
		color.Fprintf(out, "%s\n", relays)
		return
	}

	relays := sc.Grab()
	if len(relays) == 0 {
		color.Fprintf(os.Stderr, "No relays are reachable this try.\n")
		os.Exit(4)
	}

	color.Printf("All reachable relays:\n")
	for _, el := range relays {
		color.Fprintf(out, "%s%s %s\n", prefix, el.Address, el.Fingerprint)
	}
	if torrc {
		color.Fprintf(out, "UseBridges 1\n")
	}
}
