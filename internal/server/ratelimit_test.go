package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestRateLimitMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("with_allowed_nets_rate_limit_not_applied", func(t *testing.T) {
		_, net1, _ := net.ParseCIDR("10.0.0.0/24")
		r := gin.New()
		r.Use(newRateLimitMiddleware([]*net.IPNet{net1}))
		r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

		// Many requests from whitelisted IP should all succeed
		for i := 0; i < 50; i++ {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "10.0.0.1:1234"
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("request %d: got status %d, want 200", i+1, rec.Code)
			}
		}
	})

	t.Run("without_allowed_nets_exceeds_limit_returns_429", func(t *testing.T) {
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
	})

	t.Run("ipRateLimiter_cleanupLocked_removes_stale_entries", func(t *testing.T) {
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
	})
}
