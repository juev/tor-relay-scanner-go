package scanner

import (
	"crypto/rand"
	"math/big"
)

func shuffle(relays Relays) {
	for i := len(relays) - 1; i > 0; i-- {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		relays[i], relays[j.Uint64()] = relays[j.Uint64()], relays[i]
	}
}
