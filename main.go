// Command 1time is the backend of the one-time secret sharing service.
//
// It exposes a small JSON API under /api/ and keeps encrypted messages in
// Redis. Static frontend files are served by nginx, not by this process.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
)

// Config holds runtime settings read from the environment.
type Config struct {
	ListenAddr    string
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	UnsecSave     bool
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
	return Config{
		ListenAddr:    getenv("LISTEN_ADDR", "127.0.0.1:8080"),
		RedisAddr:     getenv("REDISHOST", "127.0.0.1:6379"),
		RedisPassword: os.Getenv("REDISPASS"),
		RedisDB:       db,
		UnsecSave:     getenv("ENABLE_UNSEC_SAVE", "0") == "1",
	}, nil
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
	if len(os.Args) > 1 {
		os.Exit(runClient(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("config", "err", err)
		os.Exit(1)
	}

	network := "tcp"
	if len(cfg.RedisAddr) > 0 && cfg.RedisAddr[0] == '/' {
		network = "unix"
	}
	rdb := redis.NewClient(&redis.Options{
		Network:  network,
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	defer rdb.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		// Not fatal: Redis may start after us, requests will fail until it is up.
		logger.Warn("redis is not reachable yet", "addr", cfg.RedisAddr, "err", err)
	}
	cancel()

	srv := newHTTPServer(cfg.ListenAddr, NewAPI(NewRedisStore(rdb), WithUnsecSave(cfg.UnsecSave)).Handler())

	go func() {
		logger.Info("listening", "addr", cfg.ListenAddr)
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
