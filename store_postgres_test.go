package main

import (
	"context"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newTestPostgres needs a real PostgreSQL: set TEST_PG_DSN, for example
// postgres://postgres@127.0.0.1:5432/onetime_test?sslmode=disable.
// Without it the PostgreSQL tests are skipped.
func newTestPostgres(t *testing.T) *PostgresStore {
	t.Helper()
	dsn := os.Getenv("TEST_PG_DSN")
	if dsn == "" {
		t.Skip("TEST_PG_DSN is not set")
	}
	ctx := context.Background()
	pg, err := NewPostgresStore(ctx, dsn, PostgresOptions{MaxConns: 20})
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.pool.Exec(ctx, "TRUNCATE messages"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pg.Close)
	return pg
}

func TestPostgresSaveAndTakeOnce(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()
	hash := sha256Hex("k1")
	id, err := pg.Save(ctx, StoredMessage{Encrypted: true, Message: "m1", HashedKey: hash}, time.Hour)
	if err != nil || len(id) != 32 {
		t.Fatalf("save: %q %v", id, err)
	}
	if res, _, err := pg.Take(ctx, id, sha256Hex("wrong")); err != nil || res != FetchWrongKey {
		t.Fatalf("wrong key: %v %v", res, err)
	}
	res, msg, err := pg.Take(ctx, id, hash)
	if err != nil || res != FetchOK || msg != "m1" {
		t.Fatalf("take: %v %q %v", res, msg, err)
	}
	if res, _, _ := pg.Take(ctx, id, hash); res != FetchNotFound {
		t.Fatalf("second take: %v", res)
	}
	if res, _, _ := pg.Take(ctx, "ffff", hash); res != FetchNotFound {
		t.Fatalf("unknown id: %v", res)
	}
}

func TestPostgresExpired(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()
	hash := sha256Hex("k")
	if ok, err := pg.insert(ctx, "dead", StoredMessage{Encrypted: true, Message: "x", HashedKey: hash}, -time.Second); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if res, _, _ := pg.Take(ctx, "dead", hash); res != FetchNotFound {
		t.Fatalf("expired message returned: %v", res)
	}
	if res, _, _ := pg.Take(ctx, "dead", sha256Hex("other")); res != FetchNotFound {
		t.Fatalf("expired message must not say wrong key: %v", res)
	}
	n, err := pg.DeleteExpired(ctx)
	if err != nil || n != 1 {
		t.Fatalf("cleanup: %d %v", n, err)
	}
}

func TestPostgresMigrateIsIdempotent(t *testing.T) {
	pg := newTestPostgres(t)
	for range 2 {
		if err := pg.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

// Two API nodes on one database: a link made on one opens on the other,
// and 50 parallel readers spread over both nodes get the message once.
func TestPostgresTwoNodes(t *testing.T) {
	pgA := newTestPostgres(t)
	pgB, err := NewPostgresStore(context.Background(), os.Getenv("TEST_PG_DSN"), PostgresOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pgB.Close)
	nodeA := httptest.NewServer(NewAPI(pgA).Handler())
	nodeB := httptest.NewServer(NewAPI(pgB).Handler())
	t.Cleanup(nodeA.Close)
	t.Cleanup(nodeB.Close)

	hash := sha256Hex("node-key")
	_, res := post(t, nodeA.URL+"/api/saveSecret", map[string]any{"secretMessage": "U2FsdGVkX1+two", "hashedKey": hash})
	id := res["newId"].(string)
	_, res = post(t, nodeB.URL+"/api/get", map[string]any{"id": id, "hashedKey": hash})
	if res["status"] != "ok" || res["cryptedMessage"] != "U2FsdGVkX1+two" {
		t.Fatalf("read on node B: %v", res)
	}

	_, res = post(t, nodeB.URL+"/api/saveSecret", map[string]any{"secretMessage": "y", "hashedKey": hash})
	id = res["newId"].(string)
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := range 50 {
		url := nodeA.URL
		if i%2 == 1 {
			url = nodeB.URL
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, r := post(t, url+"/api/get", map[string]any{"id": id, "hashedKey": hash})
			if r["status"] == "ok" {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("message was read %d times, want 1", ok.Load())
	}

	resp, err := nodeB.Client().Get(nodeB.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health: %d", resp.StatusCode)
	}
}

func TestPostgresUnsecSaveRoundTrip(t *testing.T) {
	pg := newTestPostgres(t)
	srv := httptest.NewServer(NewAPI(pg).Handler())
	t.Cleanup(srv.Close)
	_, res := post(t, srv.URL+"/api/unsecSave", map[string]any{"secretMessage": "hi", "duration": 60})
	if res["status"] != "ok" {
		t.Fatalf("unsecSave: %v", res)
	}
	link := res["newLink"].(string)[len("/v/#"):]
	_, got := post(t, srv.URL+"/api/get", map[string]any{"id": link[randKeyLen:], "hashedKey": sha256Hex(link[:randKeyLen])})
	if got["status"] != "ok" {
		t.Fatalf("get: %v", got)
	}
}

// Links issued while the service ran on Redis must open after the move.
func TestMigrateRedisToPostgres(t *testing.T) {
	pg := newTestPostgres(t)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	ctx := context.Background()

	hash := sha256Hex("abcdefghijkl")
	legacy := `{"encrypted":true,"message":"U2FsdGVkX19old","hashedKey":"` + hash + `"}`
	rdb.Set(ctx, "messageKey1a", legacy, 2*time.Hour)                             // old counter id
	rdb.Set(ctx, "messageKey0123456789abcdef0123456789abcdef", legacy, time.Hour) // new random id
	rdb.Set(ctx, "messageKeyff", legacy, 0)                                       // no TTL
	rdb.Set(ctx, "messageKeybad", "not json", time.Hour)                          // broken
	rdb.Set(ctx, "otherKey", "x", time.Hour)                                      // not ours

	st, err := migrateRedisToPostgres(ctx, rdb, pg)
	if err != nil {
		t.Fatal(err)
	}
	if st.Copied != 3 || st.Skipped != 1 || st.Scanned != 4 {
		t.Fatalf("stats: %+v", st)
	}
	st, err = migrateRedisToPostgres(ctx, rdb, pg)
	if err != nil || st.Copied != 0 || st.Existing != 3 {
		t.Fatalf("second run: %+v %v", st, err)
	}

	var left time.Duration
	if err := pg.pool.QueryRow(ctx,
		"SELECT expires_at - now() FROM messages WHERE id = '1a'").Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left < 119*time.Minute || left > 2*time.Hour {
		t.Fatalf("ttl not kept: %v", left)
	}

	srv := httptest.NewServer(NewAPI(pg).Handler())
	t.Cleanup(srv.Close)
	for _, id := range []string{"1a", "0123456789abcdef0123456789abcdef", "ff"} {
		_, res := post(t, srv.URL+"/api/get", map[string]any{"id": id, "hashedKey": hash})
		if res["status"] != "ok" || res["cryptedMessage"] != "U2FsdGVkX19old" {
			t.Fatalf("id %s after migration: %v", id, res)
		}
	}
}

func TestLoadConfigStore(t *testing.T) {
	t.Setenv("STORE", "postgres")
	t.Setenv("DATABASE_URL", "")
	if _, err := loadConfig(); err == nil {
		t.Fatal("postgres without DATABASE_URL must fail")
	}
	t.Setenv("DATABASE_URL", "postgres://u@h/db")
	cfg, err := loadConfig()
	if err != nil || cfg.Store != "postgres" || !cfg.DBMigrate || cfg.CleanupInterval != 10*time.Minute {
		t.Fatalf("%+v %v", cfg, err)
	}
	t.Setenv("STORE", "mysql")
	if _, err := loadConfig(); err == nil {
		t.Fatal("unknown store accepted")
	}
	t.Setenv("STORE", "")
	if cfg, _ := loadConfig(); cfg.Store != "redis" {
		t.Fatal("default store must stay redis")
	}
}
