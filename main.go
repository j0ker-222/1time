// Command 1time is the backend of the one-time secret sharing service.
//
// It exposes a small JSON API under /api/ and keeps encrypted messages in
// Redis (one server) or PostgreSQL (one or several servers behind a load
// balancer). Static frontend files are served by nginx, not by this process.
//
// Usage:
//
//	1time                  run the API server
//	1time migrate-redis    copy messages from Redis to PostgreSQL and exit
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
)

// Config holds runtime settings read from the environment.
type Config struct {
	ListenAddr string
	// Store is "redis" (default, single server) or "postgres".
	Store string

	RedisAddr     string
	RedisPassword string
	RedisDB       int

	DatabaseURL     string
	PGMaxConns      int32
	DBMigrate       bool
	CleanupInterval time.Duration
}

func getenv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func loadConfig() (Config, error) {
	db, err := strconv.Atoi(getenv("REDISDB", "0"))
	if err != nil {
		return Config{}, errors.New("REDISDB must be an integer")
	}
	maxConns, err := strconv.Atoi(getenv("PG_MAX_CONNS", "10"))
	if err != nil || maxConns < 1 {
		return Config{}, errors.New("PG_MAX_CONNS must be a positive integer")
	}
	migrate, err := strconv.ParseBool(getenv("DB_MIGRATE", "true"))
	if err != nil {
		return Config{}, errors.New("DB_MIGRATE must be true or false")
	}
	cleanup, err := time.ParseDuration(getenv("CLEANUP_INTERVAL", "10m"))
	if err != nil {
		return Config{}, errors.New("CLEANUP_INTERVAL must be a duration such as 10m (0 disables)")
	}
	cfg := Config{
		ListenAddr:      getenv("LISTEN_ADDR", "127.0.0.1:8080"),
		Store:           strings.ToLower(getenv("STORE", "redis")),
		RedisAddr:       getenv("REDISHOST", "127.0.0.1:6379"),
		RedisPassword:   os.Getenv("REDISPASS"),
		RedisDB:         db,
		DatabaseURL:     os.Getenv("DATABASE_URL"),
		PGMaxConns:      int32(maxConns),
		DBMigrate:       migrate,
		CleanupInterval: cleanup,
	}
	switch cfg.Store {
	case "redis":
	case "postgres", "postgresql":
		cfg.Store = "postgres"
		if cfg.DatabaseURL == "" {
			return Config{}, errors.New("STORE=postgres needs DATABASE_URL")
		}
	default:
		return Config{}, fmt.Errorf("unknown STORE %q (redis or postgres)", cfg.Store)
	}
	return cfg, nil
}

func newRedisClient(cfg Config) *redis.Client {
	network := "tcp"
	if len(cfg.RedisAddr) > 0 && cfg.RedisAddr[0] == '/' {
		network = "unix"
	}
	return redis.NewClient(&redis.Options{
		Network:  network,
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
}

func openPostgres(ctx context.Context, cfg Config, logger *slog.Logger) (*PostgresStore, error) {
	pg, err := NewPostgresStore(ctx, cfg.DatabaseURL, PostgresOptions{MaxConns: cfg.PGMaxConns})
	if err != nil {
		return nil, err
	}
	if cfg.DBMigrate {
		mctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := pg.Migrate(mctx)
		cancel()
		if err != nil {
			pg.Close()
			return nil, fmt.Errorf("apply schema: %w", err)
		}
		logger.Info("database schema is up to date")
	}
	return pg, nil
}

func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("config", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "migrate-redis":
			os.Exit(runMigrateRedis(ctx, cfg, logger))
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q\nusage: 1time [migrate-redis]\n", os.Args[1])
			os.Exit(2)
		}
	}

	var store Store
	switch cfg.Store {
	case "postgres":
		pg, err := openPostgres(ctx, cfg, logger)
		if err != nil {
			logger.Error("postgres", "err", err)
			os.Exit(1)
		}
		defer pg.Close()
		go pg.RunCleanup(ctx, cfg.CleanupInterval)
		store = pg
	default:
		rdb := newRedisClient(cfg)
		defer rdb.Close()
		store = NewRedisStore(rdb)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	if err := store.Ping(pingCtx); err != nil {
		// Not fatal: the storage may start after us, requests fail until it is up.
		logger.Warn("storage is not reachable yet", "store", cfg.Store, "err", err)
	}
	cancel()

	srv := newHTTPServer(cfg.ListenAddr, NewAPI(store).Handler())

	go func() {
		logger.Info("listening", "addr", cfg.ListenAddr, "store", cfg.Store)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown", "err", err)
	}
	logger.Info("stopped")
}

// runMigrateRedis copies messages from Redis (REDISHOST, REDISPASS,
// REDISDB) to PostgreSQL (DATABASE_URL). It ignores STORE.
func runMigrateRedis(ctx context.Context, cfg Config, logger *slog.Logger) int {
	if cfg.DatabaseURL == "" {
		logger.Error("migrate-redis needs DATABASE_URL")
		return 1
	}
	rdb := newRedisClient(cfg)
	defer rdb.Close()
	if err := rdb.Ping(ctx).Err(); err != nil {
		logger.Error("redis", "addr", cfg.RedisAddr, "err", err)
		return 1
	}
	cfg.DBMigrate = true
	pg, err := openPostgres(ctx, cfg, logger)
	if err != nil {
		logger.Error("postgres", "err", err)
		return 1
	}
	defer pg.Close()
	st, err := migrateRedisToPostgres(ctx, rdb, pg)
	logger.Info("migrate-redis", "scanned", st.Scanned, "copied", st.Copied,
		"already_in_postgres", st.Existing, "skipped", st.Skipped)
	if err != nil {
		logger.Error("migrate-redis", "err", err)
		return 1
	}
	return 0
}
