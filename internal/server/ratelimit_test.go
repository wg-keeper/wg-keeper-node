package server

import (
	"fmt"
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
	r.Use(newRateLimitMiddleware([]*net.IPNet{net1}))
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
	r.Use(newRateLimitMiddleware(nil))
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

func TestIPRateLimiterCleanupTriggeredAtThreshold(t *testing.T) {
	limiter := newIPRateLimiter(rateLimitRPS, rateLimitBurst)
	now := time.Now()

	// Pre-fill the map just above threshold with stale entries
	limiter.mu.Lock()
	for i := 0; i <= rateLimiterCleanupThreshold; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		limiter.limiters[ip] = &ipLimiter{
			limiter:  rate.NewLimiter(limiter.limit, limiter.burst),
			lastSeen: now.Add(-2 * rateLimiterTTL), // stale
		}
	}
	limiter.mu.Unlock()

	// get() for a new IP should trigger cleanupLocked since len > threshold
	_ = limiter.get("192.0.2.99")

	limiter.mu.RLock()
	remaining := len(limiter.limiters)
	limiter.mu.RUnlock()

	// All stale entries should be gone; only the newly added IP remains
	if remaining != 1 {
		t.Errorf("expected 1 entry after cleanup (new IP), got %d", remaining)
	}
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
