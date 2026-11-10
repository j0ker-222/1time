package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"crypto/sha256"
	"encoding/hex"

	"1time/internal/otcrypto"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newTestRedis uses a real Redis when TEST_REDIS_ADDR is set (CI and local
// runs), otherwise an in-process miniredis.
func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	if addr := os.Getenv("TEST_REDIS_ADDR"); addr != "" {
		rdb := redis.NewClient(&redis.Options{Addr: addr, DB: 15})
		if err := rdb.FlushDB(context.Background()).Err(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		t.Cleanup(func() { rdb.FlushDB(context.Background()); rdb.Close() })
		return rdb
	}
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	return rdb
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func newTestServer(t *testing.T, opts ...APIOption) (*httptest.Server, *redis.Client) {
	t.Helper()
	rdb := newTestRedis(t)
	srv := httptest.NewServer(NewAPI(NewRedisStore(rdb), opts...).Handler())
	t.Cleanup(srv.Close)
	return srv, rdb
}

func post(t *testing.T, url string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestSaveAndGetOnce(t *testing.T) {
	srv, _ := newTestServer(t)
	hash := sha256Hex("secretKEY12345")

	code, res := post(t, srv.URL+"/api/saveSecret", map[string]any{
		"secretMessage": "U2FsdGVkX1+ciphertext", "hashedKey": hash, "duration": 86400,
	})
	if code != 200 || res["status"] != "ok" {
		t.Fatalf("save: %d %v", code, res)
	}
	id := res["newId"].(string)
	if !reMessageID.MatchString(id) || len(id) != 32 {
		t.Fatalf("bad id %q", id)
	}

	_, res = post(t, srv.URL+"/api/get", map[string]any{"id": id, "hashedKey": sha256Hex("wrong")})
	if res["status"] != "wrong key" {
		t.Fatalf("wrong key: %v", res)
	}
	_, res = post(t, srv.URL+"/api/get", map[string]any{"id": id, "hashedKey": hash})
	if res["status"] != "ok" || res["cryptedMessage"] != "U2FsdGVkX1+ciphertext" {
		t.Fatalf("get: %v", res)
	}
	_, res = post(t, srv.URL+"/api/get", map[string]any{"id": id, "hashedKey": hash})
	if res["status"] != "no message" {
		t.Fatalf("second get must fail: %v", res)
	}
}

func TestConcurrentReadsReturnMessageOnce(t *testing.T) {
	srv, _ := newTestServer(t)
	hash := sha256Hex("k")
	_, res := post(t, srv.URL+"/api/saveSecret", map[string]any{"secretMessage": "x", "hashedKey": hash})
	id := res["newId"].(string)

	var ok atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, r := post(t, srv.URL+"/api/get", map[string]any{"id": id, "hashedKey": hash})
			if r["status"] == "ok" {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("message was read %d times, want 1", ok.Load())
	}
}

func TestLegacyMessageStillReadable(t *testing.T) {
	srv, rdb := newTestServer(t)
	// Format written by the previous version: counter id, same JSON fields.
	hash := sha256Hex("abcdefghijkl")
	old := `{"encrypted":true,"message":"U2FsdGVkX19old","hashedKey":"` + hash + `"}`
	if err := rdb.Set(context.Background(), "messageKey1a", old, time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
	_, res := post(t, srv.URL+"/api/get", map[string]any{"id": "1a", "hashedKey": hash})
	if res["status"] != "ok" || res["cryptedMessage"] != "U2FsdGVkX19old" {
		t.Fatalf("legacy get: %v", res)
	}
}

func TestUnsecSaveDisabledByDefault(t *testing.T) {
	srv, _ := newTestServer(t)
	code, _ := post(t, srv.URL+"/api/unsecSave", map[string]any{"secretMessage": "x"})
	if code != http.StatusNotFound {
		t.Fatalf("unsecSave must be off by default, got %d", code)
	}
}

func TestUnsecSaveV2RoundTrip(t *testing.T) {
	srv, rdb := newTestServer(t, WithUnsecSave(true))
	_, res := post(t, srv.URL+"/api/unsecSave", map[string]any{"secretMessage": "Привет из API"})
	if res["status"] != "ok" {
		t.Fatalf("unsecSave: %v", res)
	}
	link := res["newLink"].(string)
	lk, id, err := otcrypto.ParseFragment(link)
	if err != nil || !strings.HasPrefix(link, "/v/#v2.") {
		t.Fatalf("link %q: %v", link, err)
	}
	stored, _ := rdb.Get(context.Background(), storeKey(id)).Result()
	if strings.Contains(stored, "Привет") || !strings.Contains(stored, `"v2:`) {
		t.Fatalf("stored value must be a v2 ciphertext: %s", stored)
	}
	keys, _ := otcrypto.Derive(lk, "")
	_, got := post(t, srv.URL+"/api/get", map[string]any{"id": id, "hashedKey": keys.Token})
	if got["status"] != "ok" {
		t.Fatalf("get: %v", got)
	}
	plain, err := otcrypto.Decrypt(keys, got["cryptedMessage"].(string))
	if err != nil || string(plain) != "Привет из API" {
		t.Fatalf("decrypt: %q %v", plain, err)
	}
}

func TestClientSendRead(t *testing.T) {
	srv, rdb := newTestServer(t)
	t.Setenv("ONETIME_SECRET", "extra key")
	var out, errb bytes.Buffer
	if rc := runClient([]string{"send", "-url", srv.URL, "-days", "1"}, strings.NewReader("секрет из скрипта"), &out, &errb); rc != 0 {
		t.Fatalf("send rc=%d %s", rc, errb.String())
	}
	link := strings.TrimSpace(out.String())
	if !strings.HasPrefix(link, srv.URL+"/v/#v2.") {
		t.Fatalf("link %q", link)
	}
	_, id, _ := otcrypto.ParseFragment(link)
	stored, _ := rdb.Get(context.Background(), storeKey(id)).Result()
	if strings.Contains(stored, "секрет") {
		t.Fatal("server must not see the plaintext")
	}
	if ttl := rdb.TTL(context.Background(), storeKey(id)).Val(); ttl > 24*time.Hour || ttl < 23*time.Hour {
		t.Fatalf("ttl %v", ttl)
	}

	t.Setenv("ONETIME_SECRET", "wrong")
	out.Reset()
	errb.Reset()
	if rc := runClient([]string{"read", link}, nil, &out, &errb); rc == 0 || !strings.Contains(errb.String(), "secret") {
		t.Fatalf("wrong secret must fail: rc=%d %s", rc, errb.String())
	}
	t.Setenv("ONETIME_SECRET", "extra key")
	out.Reset()
	if rc := runClient([]string{"read", link}, nil, &out, &errb); rc != 0 || out.String() != "секрет из скрипта" {
		t.Fatalf("read rc=%d out=%q err=%s", rc, out.String(), errb.String())
	}
	errb.Reset()
	if rc := runClient([]string{"read", link}, nil, &out, &errb); rc == 0 || !strings.Contains(errb.String(), "destroyed") {
		t.Fatalf("second read must fail: %s", errb.String())
	}
}

func TestRejectsNonJSONAndOversize(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, err := http.Post(srv.URL+"/api/saveSecret", "text/plain", strings.NewReader(`{"secretMessage":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain: got %d", resp.StatusCode)
	}

	big := `{"secretMessage":"` + strings.Repeat("a", maxBodyBytes+10) + `"}`
	resp, err = http.Post(srv.URL+"/api/saveSecret", "application/json", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize: got %d", resp.StatusCode)
	}

	resp, err = http.Get(srv.URL + "/api/get")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/get: got %d", resp.StatusCode)
	}
}

func TestValidation(t *testing.T) {
	srv, _ := newTestServer(t)
	code, _ := post(t, srv.URL+"/api/saveSecret", map[string]any{"secretMessage": "x", "hashedKey": "nothex"})
	if code != http.StatusBadRequest {
		t.Fatalf("bad hash accepted: %d", code)
	}
	_, res := post(t, srv.URL+"/api/get", map[string]any{"id": "../etc", "hashedKey": sha256Hex("a")})
	if res["status"] != "no message" {
		t.Fatalf("bad id: %v", res)
	}
}

func TestTTL(t *testing.T) {
	if ttlFromSeconds(0) != defaultDuration || ttlFromSeconds(-5) != defaultDuration {
		t.Fatal("default ttl")
	}
	if ttlFromSeconds(31*86400) != defaultDuration {
		t.Fatal("ttl above max must fall back to default")
	}
	if ttlFromSeconds(86400) != 24*time.Hour {
		t.Fatal("1 day")
	}
}

func TestHealth(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, err := http.Get(srv.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("health: %d %v", resp.StatusCode, resp.Header)
	}
}
