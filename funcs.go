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
