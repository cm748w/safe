package server

import (
	"hash/fnv"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Rate limiting defaults. 20 requests/s with a burst of 40 keeps a well-behaved
// caller under the limit while still letting short spikes through.
const (
	defaultRateLimitPerSec = 20.0
	defaultRateLimitBurst  = 40

	// numLimitShards spreads client state over independent mutexes so a burst of
	// distinct source IPs does not serialise on a single lock.
	numLimitShards = 16

	// rateLimitEntryTTL is how long an idle client bucket is retained. It is
	// derived from the refill rate (see cleanupInterval) so a retained entry is
	// always equivalent to a freshly created one.
	rateLimitEntryTTL = 10 * time.Minute

	// defaultSweepInterval is the shortest gap between two eviction passes over
	// the same shard. Sweeps are triggered by incoming requests rather than by a
	// background goroutine, so an idle server performs no work at all.
	defaultSweepInterval = 30 * time.Second
)

// limiterOptions carries the internal knobs of a limiter. They are resolved by
// New; tests override them to drive the clock and to make eviction observable
// without sleeping.
type limiterOptions struct {
	perSec float64
	burst  int
	now    func() time.Time
	ttl    time.Duration
	sweep  time.Duration
	shards int
}

// bucket is the token-bucket state of a single client.
type bucket struct {
	tokens float64
	last   time.Time
}

// limitShard owns one slice of the client table plus its own lock and sweeper
// bookkeeping, so sweeps stay cheap and never block unrelated shards.
type limitShard struct {
	mu        sync.Mutex
	clients   map[string]*bucket
	lastSweep time.Time
}

// RateLimiter is a concurrency-safe, per-client-IP token bucket.
//
// It is safe for concurrent use. Each client gets an independent bucket, and
// idle buckets are evicted lazily (at most one sweep per sweep interval) so the
// client table cannot grow without bound under source-IP churn.
type RateLimiter struct {
	perSec   float64
	burst    float64
	ttl      time.Duration
	sweep    time.Duration
	now      func() time.Time
	shards   []*limitShard
	shardCnt uint32
}

// newRateLimiter builds a limiter from resolved options. A non-positive rate
// disables limiting (Allow always permits); callers use that for "unlimited".
func newRateLimiter(opts limiterOptions) *RateLimiter {
	n := opts.shards
	if n <= 0 {
		n = numLimitShards
	}
	shards := make([]*limitShard, n)
	for i := range shards {
		shards[i] = &limitShard{
			clients:   make(map[string]*bucket),
			lastSweep: opts.now(),
		}
	}
	burst := float64(opts.burst)
	if burst < 1 {
		burst = 1
	}
	return &RateLimiter{
		perSec: opts.perSec,
		burst:  burst,
		ttl:    opts.ttl,
		sweep:  opts.sweep,
		now:    opts.now,
		shards: shards,
		//nolint:gosec // G115: n is bounded by the shard count and always positive.
		shardCnt: uint32(n),
	}
}

// cleanupInterval derives an eviction age from the refill rate: after this long
// an untouched bucket has fully refilled, so dropping it is indistinguishable
// from keeping it.
func cleanupInterval(perSec float64, burst int) time.Duration {
	if perSec <= 0 {
		return rateLimitEntryTTL
	}
	ttl := time.Duration(float64(burst)/perSec*float64(time.Second)) * 3
	if ttl < rateLimitEntryTTL {
		return rateLimitEntryTTL
	}
	return ttl
}

// shardFor maps a client key onto its shard with FNV-1a.
func (l *RateLimiter) shardFor(key string) *limitShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return l.shards[h.Sum32()%l.shardCnt]
}

// Allow consumes one token for key. The second result reports how long the
// caller should wait before retrying; it is zero when the request is allowed.
func (l *RateLimiter) Allow(key string) (bool, time.Duration) {
	if l.perSec <= 0 {
		return true, 0
	}
	now := l.now()
	sh := l.shardFor(key)

	sh.mu.Lock()
	defer sh.mu.Unlock()

	l.sweepLocked(sh, now)

	b, ok := sh.clients[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		sh.clients[key] = b
	} else {
		// A clock that jumps backwards must not hand out free tokens.
		if elapsed := now.Sub(b.last); elapsed > 0 {
			b.tokens += elapsed.Seconds() * l.perSec
			if b.tokens > l.burst {
				b.tokens = l.burst
			}
			b.last = now
		}
	}

	if b.tokens < 1 {
		// Seconds needed to accumulate the missing fraction of a token.
		wait := (1 - b.tokens) / l.perSec
		return false, time.Duration(wait * float64(time.Second))
	}
	b.tokens--
	return true, 0
}

// sweepLocked evicts idle buckets from one shard, at most once per sweep
// interval. It runs under the shard lock; the table slice it walks is small
// enough that the pass is cheap, and the interval bounds how often it happens.
//
// Note that a request only ever sweeps the single shard its own key hashes to,
// which is what keeps the steady-state cost O(1) per request. Idle shards are
// therefore reclaimed the next time any client hashing into them is seen, not
// by some global pass.
func (l *RateLimiter) sweepLocked(sh *limitShard, now time.Time) {
	if l.sweep <= 0 || l.ttl <= 0 {
		return
	}
	if now.Sub(sh.lastSweep) < l.sweep {
		return
	}
	for key, b := range sh.clients {
		if now.Sub(b.last) > l.ttl {
			delete(sh.clients, key)
		}
	}
	sh.lastSweep = now
}

// len reports the number of tracked clients across all shards. It is only used
// by tests to assert that idle clients are evicted.
func (l *RateLimiter) len() int {
	total := 0
	for _, sh := range l.shards {
		sh.mu.Lock()
		total += len(sh.clients)
		sh.mu.Unlock()
	}
	return total
}

// clientIP returns the rate-limiting key for a request.
//
// Only the host part of RemoteAddr is used: net/http fills it from the accepted
// TCP connection, so it cannot be forged by the caller. X-Forwarded-For and
// friends are deliberately ignored — they are client-controlled strings, and
// trusting them would let anyone rotate a fake header to bypass the limit
// entirely. Deployments behind a reverse proxy should therefore either terminate
// rate limiting at the proxy or normalise RemoteAddr there (for example by
// making the proxy the only reachable peer).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr may already be a bare host (custom listeners, tests).
		host = r.RemoteAddr
	}
	if host == "" {
		return "unknown"
	}
	return host
}

// retryAfterSeconds renders a retry delay as the whole-second value required by
// the Retry-After header, always at least 1 so clients do not hot-loop.
func retryAfterSeconds(d time.Duration) string {
	secs := int((d + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	return strconv.Itoa(secs)
}

// rateLimitMiddleware rejects requests beyond the per-client-IP budget with 429
// and a Retry-After header.
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Liveness probes must never be throttled: an overloaded server still has
		// to answer them, or orchestrators would restart a healthy process.
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		if ok, retryAfter := s.limiter.Allow(clientIP(r)); !ok {
			w.Header().Set("Retry-After", retryAfterSeconds(retryAfter))
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}
