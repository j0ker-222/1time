package otcrypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Shared with frontend/src/lib/cryptoV2.test.js: the browser must derive the
// same token and produce the same payload for the same inputs and IV.
const (
	vecLinkKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	vecIVHex      = "a0a1a2a3a4a5a6a7a8a9aaab"
	vecText       = "Привет, 1time v2!"
	vecSecret     = "correct horse"

	vecTokenNoSecret   = "692195aedeeaec0ac11b9524076f43bb2c4cb99fe26896044e9da1b823d5ede0"
	vecPayloadNoSecret = "v2:oKGio6SlpqeoqaqrA14HlIi5DmmE3y3iA1A3RDDfkkskG5oIrAUqDQ1Ry7aCWYJarIOp"
	vecTokenSecret     = "63ee307f23de4aee4f2bfac590504cdad8269f08e7549eb5c22960c4ca81d82f"
	vecPayloadSecret   = "v2:oKGio6Slpqeoqaqr1OEWbNACI9Z1WkAIFNdxsknHNvTB76+A21XimRl8XbToLxAxBzxb"

	// Produced by the browser implementation (random IV), decrypted here.
	jsLinkKeyB64 = "KNWg7ciH_4akkEzgrN-6w9n3WzXFZpcY6lNASfodaps"
	jsSecret     = "s3cret"
	jsPayload    = "v2:ckvmVB9zIZ4DuJBEnnDGjDhSiKMj3LPQoRUKkSgJdP09EylVtgQlEE68oJmnnfWLng=="
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRoundTrip(t *testing.T) {
	for _, secret := range []string{"", "extra key"} {
		lk, _ := NewLinkKey()
		k, err := Derive(lk, secret)
		if err != nil {
			t.Fatal(err)
		}
		if len(k.Token) != 64 || len(k.Enc) != 32 {
			t.Fatalf("bad sizes: %d %d", len(k.Token), len(k.Enc))
		}
		p, err := Encrypt(k, []byte(vecText))
		if err != nil || !strings.HasPrefix(p, PayloadPrefix) {
			t.Fatal(p, err)
		}
		out, err := Decrypt(k, p)
		if err != nil || string(out) != vecText {
			t.Fatalf("%q %v", out, err)
		}
	}
}

func TestSecretChangesKeys(t *testing.T) {
	lk, _ := NewLinkKey()
	a, _ := Derive(lk, "")
	b, _ := Derive(lk, "x")
	c, _ := Derive(lk, "y")
	if a.Token == b.Token || b.Token == c.Token || bytes.Equal(b.Enc, c.Enc) {
		t.Fatal("secret must change token and key")
	}
	if a.Token == hex.EncodeToString(a.Enc) {
		t.Fatal("token must not equal the encryption key")
	}
	p, _ := Encrypt(b, []byte("m"))
	if _, err := Decrypt(c, p); err != ErrDecrypt {
		t.Fatalf("wrong secret must fail authentication, got %v", err)
	}
}

func TestTamperDetected(t *testing.T) {
	lk, _ := NewLinkKey()
	k, _ := Derive(lk, "")
	p, _ := Encrypt(k, []byte("do not change me"))
	raw := []byte(p)
	// flip one bit in every position of the base64 body
	for i := len(PayloadPrefix); i < len(raw)-2; i++ {
		mod := append([]byte(nil), raw...)
		if mod[i] == 'A' {
			mod[i] = 'B'
		} else {
			mod[i] = 'A'
		}
		if out, err := Decrypt(k, string(mod)); err == nil {
			t.Fatalf("modification at %d not detected: %q", i, out)
		}
	}
}

func TestLinkFragment(t *testing.T) {
	lk, _ := NewLinkKey()
	f := Fragment(lk, "0123abcd")
	if !strings.HasPrefix(f, "v2.") || len(f) != 3+43+1+8 {
		t.Fatalf("fragment %q", f)
	}
	for _, in := range []string{f, "#" + f, "https://x/v/#" + f} {
		k, id, err := ParseFragment(in)
		if err != nil || !bytes.Equal(k, lk) || id != "0123abcd" {
			t.Fatalf("%q: %v", in, err)
		}
	}
	for _, bad := range []string{"", "abcdefghijkl1f", "v2.short.1", "v2." + strings.Repeat("A", 43)} {
		if _, _, err := ParseFragment(bad); err == nil {
			t.Fatalf("%q must fail", bad)
		}
	}
}

func TestVectors(t *testing.T) {
	lk := mustHex(t, vecLinkKeyHex)
	iv := mustHex(t, vecIVHex)
	for _, c := range []struct{ secret, token, payload string }{
		{"", vecTokenNoSecret, vecPayloadNoSecret},
		{vecSecret, vecTokenSecret, vecPayloadSecret},
	} {
		k, err := Derive(lk, c.secret)
		if err != nil {
			t.Fatal(err)
		}
		p, err := encryptWithIV(k, iv, []byte(vecText))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("secret=%q token=%s payload=%s", c.secret, k.Token, p)
		if k.Token != c.token || p != c.payload {
			t.Errorf("vector mismatch for secret %q", c.secret)
		}
	}
}

func TestDecryptBrowserPayload(t *testing.T) {
	lk, _, err := ParseFragment("v2." + jsLinkKeyB64 + ".1")
	if err != nil {
		t.Fatal(err)
	}
	k, _ := Derive(lk, jsSecret)
	out, err := Decrypt(k, jsPayload)
	if err != nil || string(out) != "из браузера" {
		t.Fatalf("%q %v", out, err)
	}
}
