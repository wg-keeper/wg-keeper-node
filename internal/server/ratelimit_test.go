package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

func TestRateLimitMiddlewareWithAllowedNets(t *testing.T) {
	gin.SetMode(gin.TestMode)

	_, net1, _ := net.ParseCIDR("10.0.0.0/24")
	r := gin.New()
	r.Use(newRateLimitMiddleware(context.Background(), []*net.IPNet{net1}))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	// Many requests from whitelisted IP should all succeed.
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("request %d: got status %d, want 200", i+1, rec.Code)
		}
	}
}

func TestRateLimitMiddlewareWithoutAllowedNetsReturns429(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(newRateLimitMiddleware(context.Background(), nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	var lastCode int
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.99.1:1234"
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		lastCode = rec.Code
		if lastCode == http.StatusTooManyRequests {
			break
		}
	}
	if lastCode != http.StatusTooManyRequests {
		t.Errorf("expected 429 after many requests, last status was %d", lastCode)
	}
}

func TestIPRateLimiterStartCleanupEvictsStale(t *testing.T) {
	limiter := newIPRateLimiter(rateLimitRPS, rateLimitBurst)

	// Add a stale entry directly.
	limiter.mu.Lock()
	limiter.limiters["192.0.2.1"] = &ipLimiter{
		limiter:  rate.NewLimiter(limiter.limit, limiter.burst),
		lastSeen: time.Now().Add(-2 * rateLimiterTTL),
	}
	limiter.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Use a very short interval so the test completes quickly.
	limiter.startCleanup(ctx, 10*time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		limiter.mu.RLock()
		remaining := len(limiter.limiters)
		limiter.mu.RUnlock()
		if remaining == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("stale entry was not evicted by background cleanup goroutine")
}

func TestIPRateLimiterCleanupLockedRemovesStaleEntries(t *testing.T) {
	limiter := newIPRateLimiter(rateLimitRPS, rateLimitBurst)
	now := time.Now()

	// Create an entry by calling get once.
	_ = limiter.get("192.0.2.1")

	limiter.mu.Lock()
	// Mark it as very old so that cleanupLocked should evict it.
	if entry, ok := limiter.limiters["192.0.2.1"]; ok {
		entry.lastSeen = now.Add(-2 * rateLimiterTTL)
	}
	limiter.cleanupLocked(now)
	remaining := len(limiter.limiters)
	limiter.mu.Unlock()

	if remaining != 0 {
		t.Fatalf("expected limiter map to be empty after cleanup, got %d entries", remaining)
	}
}
