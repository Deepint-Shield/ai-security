package cache

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisOptions configure a redis-backed cache. Only Addr is required;
// the rest carry sensible defaults that match a single-instance
// production deployment.
type RedisOptions struct {
	// Addr is the redis target, e.g. "redis.internal:6379". For
	// cluster mode supply a comma-separated list (handled by the
	// caller - wrap NewRedis with their own cluster constructor).
	Addr string
	// Username + Password - leave empty for an unauthenticated
	// localhost dev deployment.
	Username string
	Password string
	// DB selects the redis logical database (0-15 by default).
	DB int
	// KeyPrefix is prepended to every key to namespace this cache
	// from other consumers of the same redis instance. Defaults to
	// "dis:" (DeepIntShield).
	KeyPrefix string
	// DefaultTTL applies when Set is called with ttl <= 0. Matches
	// the in-memory implementation default (60s).
	DefaultTTL time.Duration
	// DialTimeout / ReadTimeout / WriteTimeout. Conservative
	// defaults so a degraded redis doesn't hold the inference path
	// hostage.
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	// PoolSize caps concurrent connections. The cache hot path is
	// ~microseconds so a pool of 50 handles 100k req/s comfortably.
	PoolSize int
}

func (o *RedisOptions) applyDefaults() {
	if o.KeyPrefix == "" {
		o.KeyPrefix = "dis:"
	}
	if o.DefaultTTL <= 0 {
		o.DefaultTTL = 60 * time.Second
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = 500 * time.Millisecond
	}
	if o.ReadTimeout <= 0 {
		o.ReadTimeout = 200 * time.Millisecond
	}
	if o.WriteTimeout <= 0 {
		o.WriteTimeout = 200 * time.Millisecond
	}
	if o.PoolSize <= 0 {
		o.PoolSize = 50
	}
}

// redisCache is the distributed implementation. Network calls go
// through go-redis with tight timeouts so cache misses degrade to
// "fall through to source of truth" rather than "block the request
// forever". The interface contract (return ErrMiss on absence) is
// preserved so swapping in for the in-memory cache is invisible to
// call sites.
type redisCache struct {
	client *redis.Client
	opts   RedisOptions
}

// NewRedis constructs a Redis-backed Cache. Returns an error only on
// failure to construct the client; connectivity is verified lazily on
// the first Get/Set so a cold redis doesn't fail server boot.
//
// Migration path from in-memory:
//
//	var c Cache
//	if redisAddr != "" {
//	    rc, err := cache.NewRedis(cache.RedisOptions{Addr: redisAddr})
//	    if err != nil { return err }
//	    c = rc
//	} else {
//	    c = cache.New(cache.Options{})
//	}
//
// All call sites operate against the Cache interface, so neither
// branch knows or cares which backend is live.
func NewRedis(opts RedisOptions) (Cache, error) {
	if opts.Addr == "" {
		return nil, errors.New("redis Addr is required")
	}
	opts.applyDefaults()
	client := redis.NewClient(&redis.Options{
		Addr:         opts.Addr,
		Username:     opts.Username,
		Password:     opts.Password,
		DB:           opts.DB,
		DialTimeout:  opts.DialTimeout,
		ReadTimeout:  opts.ReadTimeout,
		WriteTimeout: opts.WriteTimeout,
		PoolSize:     opts.PoolSize,
	})
	return &redisCache{client: client, opts: opts}, nil
}

func (r *redisCache) key(k string) string {
	return r.opts.KeyPrefix + k
}

func (r *redisCache) Get(ctx context.Context, key string) ([]byte, error) {
	if key == "" {
		return nil, ErrMiss
	}
	val, err := r.client.Get(ctx, r.key(key)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrMiss
		}
		// Any other error (timeout, connection refused) - treat as a
		// miss so the caller falls through to the source of truth.
		// This is a deliberate design: a degraded redis must not
		// degrade the actual product behaviour. We don't even log
		// here because the redis client itself emits metrics.
		return nil, ErrMiss
	}
	return val, nil
}

func (r *redisCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if key == "" {
		return nil
	}
	if ttl <= 0 {
		ttl = r.opts.DefaultTTL
	}
	// Best-effort write - same degradation policy as Get. If redis is
	// down the next request will compute the value again.
	_ = r.client.Set(ctx, r.key(key), value, ttl).Err()
	return nil
}

func (r *redisCache) Delete(ctx context.Context, key string) error {
	if key == "" {
		return nil
	}
	_ = r.client.Del(ctx, r.key(key)).Err()
	return nil
}

func (r *redisCache) Close() error {
	if r.client == nil {
		return nil
	}
	return r.client.Close()
}
