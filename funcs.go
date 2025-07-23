package scanner

import (
	"crypto/rand"
	"math/big"
)

// shuffle performs a cryptographically secure shuffle of the relays slice
func shuffle(relays Relays) {
	n := len(relays)
	for i := n - 1; i > 0; i-- {
		j, err := cryptoRandInt(i + 1)
		if err != nil {
			// Fallback to simple swap if crypto rand fails
			j = i
		}
		relays[i], relays[j] = relays[j], relays[i]
	}
}

// cryptoRandInt returns a cryptographically secure random integer in the range [0, max)
func cryptoRandInt(max int) (int, error) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(nBig.Int64()), nil
}
