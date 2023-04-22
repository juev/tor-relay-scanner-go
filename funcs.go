package scanner

import (
	"math/rand"
	"time"
)

func shuffle(relays Relays) {
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(relays), func(i, j int) {
		relays[i], relays[j] = relays[j], relays[i]
	})
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
