package scanner

import (
	"net/url"
	"slices"
	"strings"
)

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
	u, err := url.Parse("//" + addr)
	if err != nil {
		// Skip the address if parsing fails
		return true
	}
	var skip bool
	if len(t.ports) > 0 &&
		!slices.Contains(t.ports, u.Port()) {
		skip = true
	}
	if len(t.excludePorts) > 0 &&
		slices.Contains(t.excludePorts, u.Port()) {
		skip = true
	}

	return skip
}

func (t *torRelayScanner) skipAddrType(addr string) bool {
	if len(addr) == 0 {
		return false
	}
	if t.ipv4 && !t.ipv6 {
		return addr[0] == '['
	}
	if t.ipv6 && !t.ipv4 {
		return addr[0] != '['
	}
	return false
}
