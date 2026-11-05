package main

import (
	"crypto/rand"
	"encoding/hex"
)

// randKeyLen is the length of the random part of the link that never
// reaches the server in the web flow. The frontend uses the same value.
const randKeyLen = 12

const keyAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// randomString returns n characters from keyAlphabet using crypto/rand.
// Rejection sampling keeps the distribution uniform.
func randomString(n int) (string, error) {
	const limit = 256 - 256%len(keyAlphabet)
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if int(b) >= limit {
				continue
			}
			out = append(out, keyAlphabet[int(b)%len(keyAlphabet)])
			if len(out) == n {
				break
			}
		}
	}
	return string(out), nil
}

// newMessageID returns a 128-bit random id in hex. Ids are no longer a
// sequential counter, so they cannot be enumerated.
func newMessageID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
