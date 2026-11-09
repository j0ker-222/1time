package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pgSchema is applied on start (DB_MIGRATE=true). It is idempotent, and an
// advisory lock keeps two nodes that start at the same time from racing.
const pgSchema = `
CREATE TABLE IF NOT EXISTS messages (
    id          text        PRIMARY KEY,
    message     text        NOT NULL,
    hashed_key  text        NOT NULL,
    encrypted   boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_expires_at_idx ON messages (expires_at);
`

// pgMigrateLockID is an arbitrary constant for pg_advisory_xact_lock.
const pgMigrateLockID = 0x1713e

// PostgresStore implements Store on top of PostgreSQL.
//
// All application nodes share one database, so a link created through one
// node can be opened through any other. Time comes from the database
// (now()), so clock skew between application nodes does not matter.
type PostgresStore struct {
	pool  *pgxpool.Pool
	newID func() (string, error)
	log   *slog.Logger
}

// PostgresOptions tune the connection pool.
type PostgresOptions struct {
	MaxConns int32
}

// NewPostgresStore opens a pool. The DSN may list several hosts, for
// example "postgres://u:p@db1,db2/onetime?target_session_attrs=read-write",
// then new connections always go to the current primary.
func NewPostgresStore(ctx context.Context, dsn string, opt PostgresOptions) (*PostgresStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	if opt.MaxConns > 0 {
		cfg.MaxConns = opt.MaxConns
	}
	// Short lifetimes make the pool forget a former primary soon after a
	// failover even if its connections were not broken.
	cfg.MaxConnLifetime = 5 * time.Minute
	cfg.MaxConnIdleTime = time.Minute
	cfg.HealthCheckPeriod = 15 * time.Second
	if cfg.ConnConfig.ConnectTimeout == 0 {
		cfg.ConnConfig.ConnectTimeout = 3 * time.Second
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &PostgresStore{pool: pool, newID: newMessageID, log: slog.Default()}, nil
}

func (s *PostgresStore) Close() { s.pool.Close() }

func (s *PostgresStore) Ping(ctx context.Context) error {
	// Ping alone would succeed on a read-only standby; writes must work.
	var ro string
	if err := s.pool.QueryRow(ctx, "SHOW transaction_read_only").Scan(&ro); err != nil {
		return err
	}
	if ro == "on" {
		return errors.New("database is read-only")
	}
	return nil
}

// Migrate creates the schema if it does not exist yet.
func (s *PostgresStore) Migrate(ctx context.Context) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", pgMigrateLockID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, pgSchema)
		return err
	})
}

func (s *PostgresStore) Save(ctx context.Context, msg StoredMessage, ttl time.Duration) (string, error) {
	for range 3 {
		id, err := s.newID()
		if err != nil {
			return "", err
		}
		ok, err := s.insert(ctx, id, msg, ttl)
		if err != nil {
			return "", err
		}
		if ok {
			return id, nil
		}
	}
	return "", errors.New("could not allocate a unique message id")
}

// insert adds a message with a given id. It returns false when the id is
// already taken (the existing row is left untouched).
func (s *PostgresStore) insert(ctx context.Context, id string, msg StoredMessage, ttl time.Duration) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
INSERT INTO messages (id, message, hashed_key, encrypted, expires_at)
VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))
ON CONFLICT (id) DO NOTHING`,
		id, msg.Message, msg.HashedKey, msg.Encrypted, ttl.Seconds())
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// Take deletes the row and returns it in one statement. Under concurrent
// readers PostgreSQL row locks let only one DELETE see the row, so a
// message is handed out at most once, whichever node serves the request.
func (s *PostgresStore) Take(ctx context.Context, id, hashedKey string) (FetchResult, string, error) {
	var msg string
	err := s.pool.QueryRow(ctx, `
DELETE FROM messages
WHERE id = $1 AND hashed_key = $2 AND expires_at > now()
RETURNING message`, id, hashedKey).Scan(&msg)
	if err == nil {
		return FetchOK, msg, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return FetchNotFound, "", err
	}
	// Separate statement on purpose: it takes a fresh snapshot, so a
	// message that a concurrent reader has just taken reads as gone, not
	// as "wrong key".
	var exists bool
	if err := s.pool.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM messages WHERE id = $1 AND expires_at > now())", id,
	).Scan(&exists); err != nil {
		return FetchNotFound, "", err
	}
	if exists {
		return FetchWrongKey, "", nil
	}
	return FetchNotFound, "", nil
}

// DeleteExpired removes expired rows and returns how many were removed.
// Expired rows are never returned by Take, this only frees space.
func (s *PostgresStore) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, "DELETE FROM messages WHERE expires_at <= now()")
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RunCleanup calls DeleteExpired every interval until ctx is done. It is
// safe to run on every node at once.
func (s *PostgresStore) RunCleanup(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := s.DeleteExpired(ctx)
			if err != nil {
				if ctx.Err() == nil {
					s.log.Warn("cleanup expired messages", "err", err)
				}
				continue
			}
			if n > 0 {
				s.log.Info("expired messages removed", "count", n)
			}
		}
	}
}
