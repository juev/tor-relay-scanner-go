package scanner

import (
	"testing"
)

func TestShuffle(t *testing.T) {
	// Create a slice of relays
	relays := Relays{
		{Fingerprint: "A", Country: "us"},
		{Fingerprint: "B", Country: "de"},
		{Fingerprint: "C", Country: "fr"},
		{Fingerprint: "D", Country: "uk"},
		{Fingerprint: "E", Country: "ca"},
	}

	// Make a copy to compare
	original := make(Relays, len(relays))
	copy(original, relays)

	// Shuffle the relays
	shuffle(relays)

	// Check that length is preserved
	if len(relays) != len(original) {
		t.Errorf("Length changed after shuffle: got %d, want %d", len(relays), len(original))
	}

	// Check that all elements are still present
	elementMap := make(map[string]bool)
	for _, relay := range relays {
		elementMap[relay.Fingerprint] = true
	}

	for _, relay := range original {
		if !elementMap[relay.Fingerprint] {
			t.Errorf("Element %s missing after shuffle", relay.Fingerprint)
		}
	}

	// Note: We can't reliably test that the order changed due to randomness,
	// but we've verified the shuffle doesn't lose or duplicate elements
}
