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

	// Format v3, shared with cryptoV2.test.js and checked with Python.
	v3LinkKeyHex = "000102030405060708090a0b0c0d0e0f"
	v3Text       = "Привет, 1time v3!"
	v3Fragment   = "AAECAwQFBgcICQoLDA0ODw"
	v3ID         = "56cbc8d3147543afd2821c6cd541f093"
	v3TokenNo    = "609a29c7f4abf75c253d3a1cc6ba59cb4d953d1776927279f1c54f5394bcc8b4"
	v3PayloadNo  = "v3:oKGio6Slpqeoqaqrc1cmHCt6HcTmSVIxTIOt7blHL+cVNzV2RJLw7wtqlB8w34W6th1d"
	v3TokenSec   = "60db59bd5688e5441a25f722bc8ffb8fb264faff95c05c072bffd71e61211428"
	v3PayloadSec = "v3:oKGio6Slpqeoqaqrh1owKmX6H+2s7uAZnATw60GI50csOlNYADb/rBjfD73DX5iKcsbU"
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
		if err != nil || !strings.HasPrefix(p, "v3:") || len(k.ID) != 32 {
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
	for i := len("v3:"); i < len(raw)-2; i++ {
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
	f := Fragment(lk, "ignored")
	if len(f) != FragmentLen || strings.ContainsAny(f, ".=+/") {
		t.Fatalf("v3 fragment %q", f)
	}
	for _, in := range []string{f, "#" + f, "https://x/v/#" + f} {
		k, id, err := ParseFragment(in)
		if err != nil || !bytes.Equal(k, lk) || id != "" {
			t.Fatalf("%q: %v", in, err)
		}
	}
	// v2 links still parse.
	lk2 := bytes.Repeat([]byte{7}, LinkKeyLenV2)
	f2 := Fragment(lk2, "0123abcd")
	if !strings.HasPrefix(f2, "v2.") || len(f2) != 3+43+1+8 {
		t.Fatalf("v2 fragment %q", f2)
	}
	if k, id, err := ParseFragment(f2); err != nil || !bytes.Equal(k, lk2) || id != "0123abcd" {
		t.Fatalf("v2 parse: %v", err)
	}
	for _, bad := range []string{"", "abcdefghijkl1f", "v2.short.1", "v2." + strings.Repeat("A", 43),
		strings.Repeat("A", 21), strings.Repeat("A", 23), strings.Repeat("A", 21) + "+"} {
		if _, _, err := ParseFragment(bad); err == nil {
			t.Fatalf("%q must fail", bad)
		}
	}
}

func TestIDDependsOnLinkKeyOnly(t *testing.T) {
	lk, _ := NewLinkKey()
	a, _ := Derive(lk, "")
	b, _ := Derive(lk, "secret")
	lk2, _ := NewLinkKey()
	c, _ := Derive(lk2, "")
	if a.ID == "" || a.ID != b.ID || a.ID == c.ID {
		t.Fatalf("ids: %q %q %q", a.ID, b.ID, c.ID)
	}
	if a.ID == a.Token[:32] {
		t.Fatal("id must be independent of the token")
	}
}

func TestVectorsV2(t *testing.T) {
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

func TestVectorsV3(t *testing.T) {
	lk := mustHex(t, v3LinkKeyHex)
	iv := mustHex(t, vecIVHex)
	if f := Fragment(lk, ""); f != v3Fragment {
		t.Fatalf("fragment %q", f)
	}
	for _, c := range []struct{ secret, token, payload string }{
		{"", v3TokenNo, v3PayloadNo},
		{vecSecret, v3TokenSec, v3PayloadSec},
	} {
		k, err := Derive(lk, c.secret)
		if err != nil {
			t.Fatal(err)
		}
		p, err := encryptWithIV(k, iv, []byte(v3Text))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("secret=%q id=%s token=%s payload=%s", c.secret, k.ID, k.Token, p)
		if k.ID != v3ID || k.Token != c.token || p != c.payload {
			t.Errorf("v3 vector mismatch for secret %q", c.secret)
		}
	}
}

func TestV2KeysDoNotOpenV3Payload(t *testing.T) {
	k2, _ := Derive(bytes.Repeat([]byte{1}, LinkKeyLenV2), "")
	k3, _ := Derive(bytes.Repeat([]byte{1}, LinkKeyLen), "")
	p, _ := Encrypt(k3, []byte("m"))
	if _, err := Decrypt(k2, p); err == nil {
		t.Fatal("v2 keys must not open a v3 payload")
	}
}
