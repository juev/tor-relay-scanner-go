package scanner

import (
	"math/rand"
	"time"
)

func shuffle(relays Relays) {
	rand.New(rand.NewSource(time.Now().UnixNano())).
		Shuffle(len(relays), func(i, j int) {
			relays[i], relays[j] = relays[j], relays[i]
		})
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
