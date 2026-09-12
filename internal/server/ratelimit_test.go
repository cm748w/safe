package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock is a manually advanced clock so limiter tests never sleep.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// testRateLimiter builds a limiter with test-friendly knobs: a settable clock,
// a 5s sweep interval and a 1min idle TTL so eviction is observable quickly.
func testRateLimiter(perSec float64, burst int, clk *fakeClock) *RateLimiter {
	return newRateLimiter(limiterOptions{
		perSec: perSec,
		burst:  burst,
		now:    clk.Now,
		ttl:    time.Minute,
		sweep:  5 * time.Second,
		shards: numLimitShards,
	})
}

func TestRateLimiterAllowsUpToBurst(t *testing.T) {
	clk := newFakeClock()
	rl := testRateLimiter(1, 3, clk)

	for i := range 3 {
		ok, retry := rl.Allow("10.0.0.1")
		if !ok {
			t.Fatalf("request %d denied, want allowed (retry after %v)", i+1, retry)
		}
		if retry != 0 {
			t.Fatalf("request %d: retryAfter = %v, want 0 when allowed", i+1, retry)
		}
	}

	ok, retry := rl.Allow("10.0.0.1")
	if ok {
		t.Fatal("4th request allowed, want denied after burst exhausted")
	}
	if retry != time.Second {
		t.Fatalf("retryAfter = %v, want 1s at 1 token/s", retry)
	}
}

func TestRateLimiterRefillsOverTime(t *testing.T) {
	clk := newFakeClock()
	rl := testRateLimiter(2, 2, clk)

	for range 2 {
		if ok, _ := rl.Allow("10.0.0.2"); !ok {
			t.Fatal("burst request denied")
		}
	}
	if ok, _ := rl.Allow("10.0.0.2"); ok {
		t.Fatal("request allowed with an empty bucket")
	}

	// Half a second at 2 tokens/s restores exactly one token.
	clk.Advance(500 * time.Millisecond)
	ok, retry := rl.Allow("10.0.0.2")
	if !ok {
		t.Fatalf("request denied after refill (retry after %v)", retry)
	}
	if ok, retry := rl.Allow("10.0.0.2"); ok {
		t.Fatal("second request allowed after consuming the single refilled token")
	} else if want := 500 * time.Millisecond; retry < want {
		t.Fatalf("retryAfter = %v, want >= %v", retry, want)
	}

	// Tokens are capped at the burst size, so a long idle period cannot bank
	// more than burst requests.
	clk.Advance(time.Hour)
	for i := range 2 {
		if ok, _ := rl.Allow("10.0.0.2"); !ok {
			t.Fatalf("request %d denied after full refill", i+1)
		}
	}
	if ok, _ := rl.Allow("10.0.0.2"); ok {
		t.Fatal("burst exceeded: tokens were not capped at the burst size")
	}
}

func TestRateLimiterIsolatesClients(t *testing.T) {
	clk := newFakeClock()
	rl := testRateLimiter(1, 1, clk)

	if ok, _ := rl.Allow("10.0.0.1"); !ok {
		t.Fatal("first client denied on its first request")
	}
	if ok, _ := rl.Allow("10.0.0.1"); ok {
		t.Fatal("first client allowed past its burst")
	}
	// A different client has its own bucket and must not be affected.
	if ok, _ := rl.Allow("10.0.0.2"); !ok {
		t.Fatal("second client denied because of the first client's budget")
	}
	if ok, _ := rl.Allow("2001:db8::1"); !ok {
		t.Fatal("IPv6 client denied because of another client's budget")
	}
}

// probeKeys returns one client key per shard. Eviction is deliberately
// per-shard (a request only sweeps the shard it hashes to), so a test that wants
// every stale entry reclaimed must drive one request into each shard.
func probeKeys(t *testing.T, rl *RateLimiter) []string {
	t.Helper()
	keys := make([]string, len(rl.shards))
	remaining := len(rl.shards)
	for i := range 10000 {
		key := fmt.Sprintf("probe-%d.example", i)
		for j, s := range rl.shards {
			if s == rl.shardFor(key) && keys[j] == "" {
				keys[j] = key
				remaining--
				break
			}
		}
		if remaining == 0 {
			return keys
		}
	}
	t.Fatal("could not find a probe key for every shard")
	return nil
}

func TestRateLimiterEvictsIdleClients(t *testing.T) {
	clk := newFakeClock()
	rl := testRateLimiter(10, 10, clk)

	for i := range 100 {
		rl.Allow(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}
	if got := rl.len(); got != 100 {
		t.Fatalf("tracked clients = %d, want 100", got)
	}

	// Past the idle TTL and with the sweep interval elapsed, the next request
	// reaching a shard triggers that shard's lazy eviction pass.
	clk.Advance(2 * time.Minute)
	for _, key := range probeKeys(t, rl) {
		rl.Allow(key)
	}

	if got := rl.len(); got != len(rl.shards) {
		t.Fatalf("tracked clients after sweeping every shard = %d, want %d (one probe per shard)",
			got, len(rl.shards))
	}
	// The survivors must be the fresh probe clients: an exhausted stale entry
	// would not have budget left on its first request.
	for _, key := range probeKeys(t, rl) {
		if ok, _ := rl.Allow(key); !ok {
			t.Fatalf("probe client %s denied after eviction sweep", key)
		}
	}
}

// TestRateLimiterSweepIsPerShard documents the eviction contract: reclaiming
// happens lazily for the shard a request hashes to, so a single request does not
// walk the whole table.
func TestRateLimiterSweepIsPerShard(t *testing.T) {
	clk := newFakeClock()
	rl := testRateLimiter(10, 10, clk)

	keys := probeKeys(t, rl)
	for _, key := range keys {
		rl.Allow(key)
	}
	if got := rl.len(); got != len(keys) {
		t.Fatalf("tracked clients = %d, want %d", got, len(keys))
	}

	clk.Advance(2 * time.Minute)
	// A single request must evict only the buckets in its own shard; the rest
	// stay until some client hashing into them shows up.
	rl.Allow(keys[0])
	if got := rl.len(); got != len(keys) {
		t.Fatalf("tracked clients after one request = %d, want %d: eviction escaped its shard",
			got, len(keys))
	}
	// Driving the remaining shards reclaims the rest.
	for _, key := range keys[1:] {
		rl.Allow(key)
	}
	if got := rl.len(); got != len(keys) {
		t.Fatalf("tracked clients after sweeping all shards = %d, want %d", got, len(keys))
	}
}

func TestRateLimiterDisabledWhenRateNonPositive(t *testing.T) {
	clk := newFakeClock()
	rl := testRateLimiter(0, 1, clk)

	for i := range 1000 {
		if ok, _ := rl.Allow("10.0.0.1"); !ok {
			t.Fatalf("request %d denied, want limiting disabled", i+1)
		}
	}
}

func TestRateLimiterConcurrentAccess(t *testing.T) {
	clk := newFakeClock()
	rl := testRateLimiter(1000, 1000, clk)

	const workers = 16
	const perWorker = 50

	var wg sync.WaitGroup
	allowed := make([]int, workers)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perWorker {
				if ok, _ := rl.Allow("10.0.0.1"); ok {
					allowed[w]++
				}
			}
		}()
	}
	wg.Wait()

	total := 0
	for _, n := range allowed {
		total += n
	}
	if total != workers*perWorker {
		t.Fatalf("allowed = %d, want %d (no request should be lost)", total, workers*perWorker)
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{name: "ipv4 with port", remoteAddr: "203.0.113.9:54321", want: "203.0.113.9"},
		{name: "ipv6 with port", remoteAddr: "[2001:db8::1]:443", want: "2001:db8::1"},
		{name: "bare host", remoteAddr: "203.0.113.9", want: "203.0.113.9"},
		{name: "empty", remoteAddr: "", want: "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/fingerprint", nil)
			r.RemoteAddr = tc.remoteAddr
			if got := clientIP(r); got != tc.want {
				t.Fatalf("clientIP(%q) = %q, want %q", tc.remoteAddr, got, tc.want)
			}
		})
	}
}

// TestClientIPIgnoresForwardedHeaders locks in the anti-spoofing decision: a
// client-supplied X-Forwarded-For must not be able to change its rate-limit key.
func TestClientIPIgnoresForwardedHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/fingerprint", nil)
	r.RemoteAddr = "203.0.113.9:54321"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "5.6.7.8")

	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("clientIP = %q, want the RemoteAddr host 203.0.113.9", got)
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		{in: 0, want: "1"},
		{in: time.Millisecond, want: "1"},
		{in: time.Second, want: "1"},
		{in: 1500 * time.Millisecond, want: "2"},
		{in: 3 * time.Second, want: "3"},
	}
	for _, tc := range tests {
		if got := retryAfterSeconds(tc.in); got != tc.want {
			t.Fatalf("retryAfterSeconds(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestCleanupInterval checks the derived TTL is never shorter than the floor and
// grows when the refill rate is slow.
func TestCleanupInterval(t *testing.T) {
	// A fast limiter floors at rateLimitEntryTTL: 40 tokens at 20/s refill in
	// 2s, so 3x that is far below the floor.
	if got := cleanupInterval(20, 40); got != rateLimitEntryTTL {
		t.Fatalf("cleanupInterval(20, 40) = %v, want the %v floor", got, rateLimitEntryTTL)
	}
	// 10 tokens at 0.2/s need 50s to refill; 3x that is 150s, still under the
	// floor, so the floor keeps winning.
	if got := cleanupInterval(0.2, 10); got != rateLimitEntryTTL {
		t.Fatalf("cleanupInterval(0.2, 10) = %v, want the %v floor", got, rateLimitEntryTTL)
	}
	// 10 tokens at 0.02/s need 500s to refill; 3x that (1500s) beats the floor.
	if got := cleanupInterval(0.02, 10); got != 1500*time.Second {
		t.Fatalf("cleanupInterval(0.02, 10) = %v, want 25m0s", got)
	}
	// A non-positive rate (limiting disabled) keeps the floor.
	if got := cleanupInterval(0, 40); got != rateLimitEntryTTL {
		t.Fatalf("cleanupInterval(0, 40) = %v, want the %v floor", got, rateLimitEntryTTL)
	}
}

// rateLimitedServer builds a test server whose limiter is driven by clk.
func rateLimitedServer(t *testing.T, perSec float64, burst int, clk *fakeClock) *Server {
	t.Helper()
	s := testServer(t)
	s.cfg.RateLimitPerSec = perSec
	s.cfg.RateLimitBurst = burst
	s.limiter = testRateLimiter(perSec, burst, clk)
	return s
}

func fingerprintRequest(remoteAddr, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(body))
	req.RemoteAddr = remoteAddr
	return req
}

func TestFingerprintRateLimited(t *testing.T) {
	clk := newFakeClock()
	s := rateLimitedServer(t, 1, 2, clk)
	handler := s.Handler()
	body := `[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]`

	for i := range 2 {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, fingerprintRequest("198.51.100.1:1234", body))
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 (body %s)", i+1, rr.Code, rr.Body.String())
		}
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, fingerprintRequest("198.51.100.1:1234", body))
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rr.Code)
	}
	if got := rr.Header().Get("Retry-After"); got == "" {
		t.Fatal("missing Retry-After header on 429")
	} else if got != "1" {
		t.Fatalf("Retry-After = %q, want \"1\"", got)
	}
	var payload map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("429 body is not JSON: %v (%s)", err, rr.Body.String())
	}
	if payload["error"] != "rate limit exceeded" {
		t.Fatalf("error = %q, want %q", payload["error"], "rate limit exceeded")
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q", ct)
	}

	// A separate client is unaffected by the first client's exhausted bucket.
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, fingerprintRequest("198.51.100.2:1234", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("other client status = %d, want 200", rr.Code)
	}

	// Once the bucket refills the original client is served again.
	clk.Advance(2 * time.Second)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, fingerprintRequest("198.51.100.1:1234", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("status after refill = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
}

// TestHealthNotRateLimited pins the requirement that probes bypass the limiter
// even while the fingerprint endpoint is saturated.
func TestHealthNotRateLimited(t *testing.T) {
	clk := newFakeClock()
	s := rateLimitedServer(t, 1, 1, clk)
	handler := s.Handler()

	// Exhaust the budget for this IP.
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, fingerprintRequest("198.51.100.1:1234", `[]`))
	if rr.Code != http.StatusOK {
		t.Fatalf("priming request status = %d, want 200", rr.Code)
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, fingerprintRequest("198.51.100.1:1234", `[]`))
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("priming request status = %d, want 429", rr.Code)
	}

	for i := range 50 {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = "198.51.100.1:1234"
		rr = httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("/health request %d: status = %d, want 200", i+1, rr.Code)
		}
	}
}

// TestDefaultRateLimitConfig checks the documented defaults survive New.
func TestDefaultRateLimitConfig(t *testing.T) {
	s := New(Config{})
	if s.cfg.RateLimitPerSec != defaultRateLimitPerSec {
		t.Fatalf("RateLimitPerSec = %v, want %v", s.cfg.RateLimitPerSec, defaultRateLimitPerSec)
	}
	if s.cfg.RateLimitBurst != defaultRateLimitBurst {
		t.Fatalf("RateLimitBurst = %d, want %d", s.cfg.RateLimitBurst, defaultRateLimitBurst)
	}
	if defaultRateLimitPerSec != 20 || defaultRateLimitBurst != 40 {
		t.Fatalf("documented defaults drifted: %v/s burst %d", defaultRateLimitPerSec, defaultRateLimitBurst)
	}
}
