package main

import (
	"fmt"
	"io"
	"os"
	"time"

	scanner "github.com/juev/tor-relay-scanner-go"
	flag "github.com/spf13/pflag"
)

var Usage = func() {
	fmt.Fprintf(os.Stdout, "Usage of tor-relay-scanner-go:\n")
	flag.PrintDefaults()
	os.Exit(0)
}

func main() {
	flag.IntVarP(&poolSize, "num_relays", "n", 30, `The number of concurrent relays tested.`)
	flag.IntVarP(&goal, "working_relay_num_goal", "g", 5, `Test until at least this number of working relays are found`)
	flag.IntVarP(&timeout, "timeout", "t", 1, `Socket connection timeout`)
	flag.StringVarP(&outfile, "outfile", "o", "", `Output reachable relays to file`)
	flag.BoolVar(&torrc, "torrc", false, `Output reachable relays in torrc format (with "Bridge" prefix)`)
	flag.StringVar(&proxy, "proxy", "", `Set proxy for onionoo information download. Format: http://user:pass@host:port; socks5h://user:pass@host:port`)
	flag.StringArrayVarP(&urls, "url", "u", []string{}, `Preferred alternative URL for onionoo relay list. Could be used multiple times.`)
	flag.StringArrayVarP(&port, "port", "p", []string{}, `Scan for relays running on specified port number. Could be used multiple times.`)
	flag.BoolVarP(&ipv4, "ipv4", "4", false, `Use ipv4 only nodes`)
	flag.Usage = Usage
	flag.Parse()

	if timeout < 1 {
		timeout = 1
	}

	sc := scanner.New(
		poolSize,
		goal,
		time.Duration(timeout)*time.Second,
		outfile,
		proxy,
		urls,
		port,
		ipv4,
	)

	var prefix string
	if torrc {
		prefix = "Bridge "
	}

	out := io.MultiWriter(os.Stdout)
	if outfile != "" {
		logFile, err := os.OpenFile(outfile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot create file (%s): %v", outfile, err)
			os.Exit(3)
		}
		out = io.MultiWriter(os.Stdout, logFile)
	}

	relays := sc.Grab()
	if len(relays) > 0 {
		fmt.Printf("All reachable relays:\n")
		for _, el := range relays {
			fmt.Fprintf(out, "%s%s %s\n", prefix, el.Addresses, el.Fingerprint)
		}
		if torrc {
			fmt.Fprintf(out, "UseBridges 1\n")
		}
	} else {
		fmt.Fprintf(os.Stderr, "No relays are reachable this try.\n")
	}
}
