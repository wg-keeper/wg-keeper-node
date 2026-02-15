package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

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
}
