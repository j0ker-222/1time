// Package otcrypto implements the "v2" message format of 1time.
//
// The same format is implemented in the browser (frontend/src/lib/cryptoV2.js)
// with Web Crypto; both sides are checked against shared test vectors.
//
// Format:
//
//	linkKey  = 32 random bytes, carried only in the URL fragment:
//	           /v/#v2.<base64url(linkKey)>.<id>
//	IKM      = linkKey                            (no additional secret)
//	IKM      = linkKey || PBKDF2-HMAC-SHA256(secret,
//	              salt = HKDF(linkKey, info "1time v2 pbkdf2 salt", 16),
//	              600000 iterations, 32 bytes)    (with additional secret)
//	encKey   = HKDF-SHA256(IKM, salt = "", info "1time v2 enc", 32)
//	token    = hex(HKDF-SHA256(IKM, salt = "", info "1time v2 auth", 32))
//	payload  = "v2:" + base64(iv(12) || AES-256-GCM(encKey, iv, text, aad "1time v2"))
//
// The server stores payload and token and returns the payload only to a
// client that presents the token. Neither value lets it decrypt: encKey and
// token are independent HKDF outputs of a 256-bit key it never sees.
package otcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	PayloadPrefix    = "v2:"
	LinkPrefix       = "v2."
	LinkKeyLen       = 32
	PBKDF2Iterations = 600000
	ivLen            = 12

	infoSalt = "1time v2 pbkdf2 salt"
	infoEnc  = "1time v2 enc"
	infoAuth = "1time v2 auth"
	aad      = "1time v2"
)

var (
	ErrBadPayload = errors.New("otcrypto: malformed payload")
	ErrDecrypt    = errors.New("otcrypto: message authentication failed")
	ErrBadLink    = errors.New("otcrypto: malformed link")
)

// Keys are the values derived from a link key and an optional secret.
type Keys struct {
	Enc   []byte // AES-256-GCM key, never leaves the client
	Token string // 64 hex chars, sent to the server as "hashedKey"
}

// NewLinkKey returns 32 random bytes.
func NewLinkKey() ([]byte, error) {
	k := make([]byte, LinkKeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// Derive computes the encryption key and the access token.
func Derive(linkKey []byte, secret string) (Keys, error) {
	if len(linkKey) != LinkKeyLen {
		return Keys{}, ErrBadLink
	}
	ikm := append([]byte(nil), linkKey...)
	if secret != "" {
		salt, err := hkdf.Key(sha256.New, linkKey, nil, infoSalt, 16)
		if err != nil {
			return Keys{}, err
		}
		p, err := pbkdf2.Key(sha256.New, secret, salt, PBKDF2Iterations, 32)
		if err != nil {
			return Keys{}, err
		}
		ikm = append(ikm, p...)
	}
	enc, err := hkdf.Key(sha256.New, ikm, nil, infoEnc, 32)
	if err != nil {
		return Keys{}, err
	}
	tok, err := hkdf.Key(sha256.New, ikm, nil, infoAuth, 32)
	if err != nil {
		return Keys{}, err
	}
	return Keys{Enc: enc, Token: hex.EncodeToString(tok)}, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Encrypt seals plaintext with a fresh random IV.
func Encrypt(k Keys, plaintext []byte) (string, error) {
	iv := make([]byte, ivLen)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	return encryptWithIV(k, iv, plaintext)
}

func encryptWithIV(k Keys, iv, plaintext []byte) (string, error) {
	a, err := gcm(k.Enc)
	if err != nil {
		return "", err
	}
	out := a.Seal(append([]byte(nil), iv...), iv, plaintext, []byte(aad))
	return PayloadPrefix + base64.StdEncoding.EncodeToString(out), nil
}

// Decrypt opens a payload; any modification of it is detected.
func Decrypt(k Keys, payload string) ([]byte, error) {
	if !strings.HasPrefix(payload, PayloadPrefix) {
		return nil, ErrBadPayload
	}
	raw, err := base64.StdEncoding.DecodeString(payload[len(PayloadPrefix):])
	if err != nil || len(raw) < ivLen+16 {
		return nil, ErrBadPayload
	}
	a, err := gcm(k.Enc)
	if err != nil {
		return nil, err
	}
	pt, err := a.Open(nil, raw[:ivLen], raw[ivLen:], []byte(aad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// Fragment builds the part of the link after "#".
func Fragment(linkKey []byte, id string) string {
	return LinkPrefix + base64.RawURLEncoding.EncodeToString(linkKey) + "." + id
}

// ParseFragment extracts the link key and message id from "v2.<key>.<id>"
// (with or without a leading "#" or a full URL in front).
func ParseFragment(s string) (linkKey []byte, id string, err error) {
	if i := strings.LastIndex(s, "#"); i >= 0 {
		s = s[i+1:]
	}
	if !strings.HasPrefix(s, LinkPrefix) {
		return nil, "", ErrBadLink
	}
	parts := strings.Split(s[len(LinkPrefix):], ".")
	if len(parts) != 2 || parts[1] == "" {
		return nil, "", ErrBadLink
	}
	k, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(k) != LinkKeyLen {
		return nil, "", ErrBadLink
	}
	return k, parts[1], nil
}
