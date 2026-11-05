package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// StoredMessage is the JSON document kept in Redis.
// The field names are unchanged from the original 1time service so that
// messages written by older versions stay readable after an upgrade.
type StoredMessage struct {
	Encrypted bool   `json:"encrypted"`
	Message   string `json:"message"`
	HashedKey string `json:"hashedKey"`
}

// FetchResult is the outcome of an attempt to read a message.
type FetchResult int

const (
	FetchNotFound FetchResult = iota
	FetchWrongKey
	FetchOK
)

// Store keeps encrypted messages.
type Store interface {
	// Save stores the message under a new random id and returns the id.
	Save(ctx context.Context, msg StoredMessage, ttl time.Duration) (string, error)
	// Take returns the message and deletes it in one atomic step, but only
	// when hashedKey matches. A wrong key leaves the message in place.
	Take(ctx context.Context, id, hashedKey string) (FetchResult, string, error)
	Ping(ctx context.Context) error
}

const storeKeyPrefix = "messageKey"

func storeKey(id string) string { return storeKeyPrefix + id }

// takeScript compares the hash and deletes the key inside Redis, so two
// concurrent readers can never both receive the same message.
var takeScript = redis.NewScript(`
local v = redis.call('GET', KEYS[1])
if not v then return {0} end
local ok, obj = pcall(cjson.decode, v)
if not ok or type(obj) ~= 'table' then return {0} end
if obj['hashedKey'] ~= ARGV[1] then return {1} end
redis.call('DEL', KEYS[1])
return {2, obj['message']}
`)

// RedisStore implements Store on top of Redis.
type RedisStore struct {
	rdb   redis.UniversalClient
	newID func() (string, error)
}

func NewRedisStore(rdb redis.UniversalClient) *RedisStore {
	return &RedisStore{rdb: rdb, newID: newMessageID}
}

func (s *RedisStore) Ping(ctx context.Context) error { return s.rdb.Ping(ctx).Err() }

func (s *RedisStore) Save(ctx context.Context, msg StoredMessage, ttl time.Duration) (string, error) {
	value, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}
	for range 3 {
		id, err := s.newID()
		if err != nil {
			return "", err
		}
		ok, err := s.rdb.SetNX(ctx, storeKey(id), value, ttl).Result()
		if err != nil {
			return "", err
		}
		if ok {
			return id, nil
		}
	}
	return "", errors.New("could not allocate a unique message id")
}

func (s *RedisStore) Take(ctx context.Context, id, hashedKey string) (FetchResult, string, error) {
	res, err := takeScript.Run(ctx, s.rdb, []string{storeKey(id)}, hashedKey).Slice()
	if err != nil {
		return FetchNotFound, "", err
	}
	if len(res) == 0 {
		return FetchNotFound, "", fmt.Errorf("unexpected script reply")
	}
	code, _ := res[0].(int64)
	switch code {
	case 2:
		msg, _ := res[1].(string)
		return FetchOK, msg, nil
	case 1:
		return FetchWrongKey, "", nil
	default:
		return FetchNotFound, "", nil
	}
}
