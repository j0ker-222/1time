// Package otcrypto implements the message formats of 1time.
//
// The same formats are implemented in the browser (frontend/src/lib/cryptoV2.js)
// with Web Crypto; both sides are checked against shared test vectors.
//
// Format v3 (current, short links):
//
//	linkKey  = 16 random bytes, the whole URL fragment: /v/#<base64url(linkKey)>
//	           (22 characters)
//	id       = hex(HKDF-SHA256(linkKey, salt = "", info "1time v3 id", 16))
//	IKM      = linkKey                            (no additional secret)
//	IKM      = linkKey || PBKDF2-HMAC-SHA256(secret,
//	              salt = HKDF(linkKey, info "1time v3 pbkdf2 salt", 16),
//	              600000 iterations, 32 bytes)    (with additional secret)
//	encKey   = HKDF-SHA256(IKM, salt = "", info "1time v3 enc", 32)
//	token    = hex(HKDF-SHA256(IKM, salt = "", info "1time v3 auth", 32))
//	payload  = "v3:" + base64(iv(12) || AES-256-GCM(encKey, iv, text, aad "1time v3"))
//
// The message id is derived from the link key on the client, so the link
// does not have to carry it. The id depends on the link key only (not on
// the additional secret), so the server can still tell "wrong key" from
// "no message".
//
// Format v2 (read only, links created on 2026-11-10): the same scheme with
// a 32-byte link key, "v2" in every info string, AAD and prefix, and a
// server-generated id carried in the link: /v/#v2.<base64url(linkKey)>.<id>
//
// The server stores payload and token and returns the payload only to a
// client that presents the token. None of id, token and payload lets it
// decrypt: they are independent HKDF outputs of a key it never sees.
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
	PBKDF2Iterations = 600000
	ivLen            = 12

	// LinkKeyLen is the link key size of the current format (v3).
	LinkKeyLen = 16
	// LinkKeyLenV2 is the link key size of format v2 (read only).
	LinkKeyLenV2 = 32
	// LinkPrefixV2 starts a v2 fragment.
	LinkPrefixV2 = "v2."
	// FragmentLen is the length of a v3 fragment (base64url of 16 bytes).
	FragmentLen = 22
)

// format holds the per-version constants.
type format struct {
	keyLen                   int
	prefix                   string // payload prefix
	salt, enc, auth, aad, id string
}

var (
	formatV2 = &format{keyLen: LinkKeyLenV2, prefix: "v2:",
		salt: "1time v2 pbkdf2 salt", enc: "1time v2 enc", auth: "1time v2 auth", aad: "1time v2"}
	formatV3 = &format{keyLen: LinkKeyLen, prefix: "v3:",
		salt: "1time v3 pbkdf2 salt", enc: "1time v3 enc", auth: "1time v3 auth", aad: "1time v3", id: "1time v3 id"}
)

func formatFor(linkKey []byte) *format {
	switch len(linkKey) {
	case LinkKeyLen:
		return formatV3
	case LinkKeyLenV2:
		return formatV2
	}
	return nil
}

var (
	ErrBadPayload = errors.New("otcrypto: malformed payload")
	ErrDecrypt    = errors.New("otcrypto: message authentication failed")
	ErrBadLink    = errors.New("otcrypto: malformed link")
)

// Keys are the values derived from a link key and an optional secret.
type Keys struct {
	Enc   []byte // AES-256-GCM key, never leaves the client
	Token string // 64 hex chars, sent to the server as "hashedKey"
	ID    string // v3: message id (32 hex chars) derived from the link key; v2: empty
	f     *format
}

// NewLinkKey returns a random link key of the current format (16 bytes).
func NewLinkKey() ([]byte, error) {
	k := make([]byte, LinkKeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// Derive computes the encryption key, the access token and (v3) the
// message id. The format is chosen by the link key size.
func Derive(linkKey []byte, secret string) (Keys, error) {
	f := formatFor(linkKey)
	if f == nil {
		return Keys{}, ErrBadLink
	}
	ikm := append([]byte(nil), linkKey...)
	if secret != "" {
		salt, err := hkdf.Key(sha256.New, linkKey, nil, f.salt, 16)
		if err != nil {
			return Keys{}, err
		}
		p, err := pbkdf2.Key(sha256.New, secret, salt, PBKDF2Iterations, 32)
		if err != nil {
			return Keys{}, err
		}
		ikm = append(ikm, p...)
	}
	enc, err := hkdf.Key(sha256.New, ikm, nil, f.enc, 32)
	if err != nil {
		return Keys{}, err
	}
	tok, err := hkdf.Key(sha256.New, ikm, nil, f.auth, 32)
	if err != nil {
		return Keys{}, err
	}
	k := Keys{Enc: enc, Token: hex.EncodeToString(tok), f: f}
	if f.id != "" {
		id, err := hkdf.Key(sha256.New, linkKey, nil, f.id, 16)
		if err != nil {
			return Keys{}, err
		}
		k.ID = hex.EncodeToString(id)
	}
	return k, nil
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
	if k.f == nil {
		return "", ErrBadLink
	}
	a, err := gcm(k.Enc)
	if err != nil {
		return "", err
	}
	out := a.Seal(append([]byte(nil), iv...), iv, plaintext, []byte(k.f.aad))
	return k.f.prefix + base64.StdEncoding.EncodeToString(out), nil
}

// Decrypt opens a payload; any modification of it is detected.
func Decrypt(k Keys, payload string) ([]byte, error) {
	if k.f == nil || !strings.HasPrefix(payload, k.f.prefix) {
		return nil, ErrBadPayload
	}
	raw, err := base64.StdEncoding.DecodeString(payload[len(k.f.prefix):])
	if err != nil || len(raw) < ivLen+16 {
		return nil, ErrBadPayload
	}
	a, err := gcm(k.Enc)
	if err != nil {
		return nil, err
	}
	pt, err := a.Open(nil, raw[:ivLen], raw[ivLen:], []byte(k.f.aad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// Fragment builds the part of the link after "#". For a v3 key it is the
// key alone (the id is derived from it); for a v2 key it also carries id.
func Fragment(linkKey []byte, id string) string {
	if len(linkKey) == LinkKeyLenV2 {
		return LinkPrefixV2 + base64.RawURLEncoding.EncodeToString(linkKey) + "." + id
	}
	return base64.RawURLEncoding.EncodeToString(linkKey)
}

// ParseFragment extracts the link key and, for v2, the message id from a
// fragment (with or without a leading "#" or a full URL in front). For v3
// the id is empty: take it from Derive.
func ParseFragment(s string) (linkKey []byte, id string, err error) {
	if i := strings.LastIndex(s, "#"); i >= 0 {
		s = s[i+1:]
	}
	if strings.HasPrefix(s, LinkPrefixV2) {
		parts := strings.Split(s[len(LinkPrefixV2):], ".")
		if len(parts) != 2 || parts[1] == "" {
			return nil, "", ErrBadLink
		}
		k, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil || len(k) != LinkKeyLenV2 {
			return nil, "", ErrBadLink
		}
		return k, parts[1], nil
	}
	if len(s) != FragmentLen {
		return nil, "", ErrBadLink
	}
	k, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(k) != LinkKeyLen {
		return nil, "", ErrBadLink
	}
	return k, "", nil
}
