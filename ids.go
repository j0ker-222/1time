package main

import (
	"crypto/rand"
	"encoding/hex"
)

// newMessageID returns a 128-bit random id in hex. Ids are not a sequential
// counter, so they cannot be enumerated.
func newMessageID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
