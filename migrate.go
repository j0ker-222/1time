package main

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/redis/go-redis/v9"
)

// MigrateStats is the outcome of copying messages from Redis to PostgreSQL.
type MigrateStats struct {
	Scanned, Copied, Existing, Skipped int
}

// migrateRedisToPostgres copies every live message from Redis into
// PostgreSQL with the same id and the remaining TTL, so links that were
// issued before the switch keep working. Rows that already exist are left
// alone, so the command can be repeated. Redis is not modified.
func migrateRedisToPostgres(ctx context.Context, rdb redis.UniversalClient, pg *PostgresStore) (MigrateStats, error) {
	var st MigrateStats
	iter := rdb.Scan(ctx, 0, storeKeyPrefix+"*", 500).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		st.Scanned++
		id := strings.TrimPrefix(key, storeKeyPrefix)
		if !reMessageID.MatchString(id) {
			st.Skipped++
			continue
		}
		raw, err := rdb.Get(ctx, key).Result()
		if err == redis.Nil {
			st.Skipped++ // read or expired while we were scanning
			continue
		}
		if err != nil {
			return st, err
		}
		ttl, err := rdb.PTTL(ctx, key).Result()
		if err != nil {
			return st, err
		}
		switch {
		case ttl == -2: // key is gone (go-redis returns -2 and -1 as raw values)
			st.Skipped++
			continue
		case ttl <= 0: // no expiry set (very old versions): give it the maximum
			ttl = maxDuration
		}
		var msg StoredMessage
		if err := json.Unmarshal([]byte(raw), &msg); err != nil || msg.Message == "" || msg.HashedKey == "" {
			st.Skipped++
			continue
		}
		ok, err := pg.insert(ctx, id, msg, ttl)
		if err != nil {
			return st, err
		}
		if ok {
			st.Copied++
		} else {
			st.Existing++
		}
	}
	return st, iter.Err()
}
