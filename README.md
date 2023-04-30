# Tor Relay Availability Checker

This is golang fork of [ValdikSS/tor-relay-scanner](https://github.com/ValdikSS/tor-relay-scanner).

---

This small program downloads all Tor Relay IP addresses from [onionoo.torproject.org](https://onionoo.torproject.org/) directly and via embedded proxies, and checks whether random Tor Relays are reachable from your Internet connection.

It could be used to find working Relay in a countries with Internet censorship and blocked Tor, and use it as Bridge to connect to Tor network, bypassing standard well-known nodes embedded into Tor code.

## How to use with Tor (daemon)

This utility is capable of generating `torrc` configuration file containing Bridge information. Launch it with the following arguments:

`--torrc --output /etc/tor/bridges.conf`

And append:

`%include /etc/tor/bridges.conf`

to the end of `/etc/tor/torrc` file to make Tor daemon load it.


## How to use as a standalone tool

**Windows**: download ***.exe** file from [Releases](https://github.com/juev/tor-relay-scanner-go/releases) and run it in console (`start → cmd`)

**Linux & macOS**: download binary file from [Releases](https://github.com/juev/tor-relay-scanner-go/releases) and run it:  

```bash
./tor-relay-scanner-go
```

Tor-relay-scanner-go gets proxy information from environment. Or you can set it from variables:

```bash
HTTP_PROXY=http://example.com:3128 HTTPS_PROXY=http://example.com:3128 ./tor-relay-scanner-go
```
