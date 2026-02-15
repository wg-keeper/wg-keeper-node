package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

const (
	middlewareTestStatusOKFmt = "status: got %d, want 200"
	middlewareTestRemoteAddr  = "10.0.0.5:1234"
)

func TestAPIKeyMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("empty_api_key_returns_500", func(t *testing.T) {
		r := gin.New()
		r.GET("/", apiKeyMiddleware(""), func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status: got %d, want 500", rec.Code)
		}
	})

	t.Run("wrong_key_returns_401", func(t *testing.T) {
		r := gin.New()
		r.GET("/", apiKeyMiddleware("secret"), func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(apiKeyHeader, "wrong")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status: got %d, want 401", rec.Code)
		}
	})

	t.Run("correct_key_calls_next", func(t *testing.T) {
		r := gin.New()
		r.GET("/", apiKeyMiddleware("secret"), func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(apiKeyHeader, "secret")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf(middlewareTestStatusOKFmt, rec.Code)
		}
	})

	t.Run("wrong_key_length_returns_401", func(t *testing.T) {
		r := gin.New()
		r.GET("/", apiKeyMiddleware("ab"), func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(apiKeyHeader, "a")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status: got %d, want 401", rec.Code)
		}
	})
}

func TestIPWhitelistMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	_, net1, _ := net.ParseCIDR("10.0.0.0/24")
	_, net2, _ := net.ParseCIDR("192.168.1.0/24")

	t.Run("nil_allowed_nets_calls_next", func(t *testing.T) {
		r := gin.New()
		r.Use(ipWhitelistMiddleware(nil))
		r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = middlewareTestRemoteAddr
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf(middlewareTestStatusOKFmt, rec.Code)
		}
	})

	t.Run("empty_allowed_nets_calls_next", func(t *testing.T) {
		r := gin.New()
		r.Use(ipWhitelistMiddleware([]*net.IPNet{}))
		r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = middlewareTestRemoteAddr
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf(middlewareTestStatusOKFmt, rec.Code)
		}
	})

	t.Run("client_ip_in_whitelist_calls_next", func(t *testing.T) {
		r := gin.New()
		r.Use(ipWhitelistMiddleware([]*net.IPNet{net1}))
		r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = middlewareTestRemoteAddr
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf(middlewareTestStatusOKFmt, rec.Code)
		}
	})

	t.Run("client_ip_not_in_whitelist_returns_403", func(t *testing.T) {
		r := gin.New()
		r.Use(ipWhitelistMiddleware([]*net.IPNet{net1}))
		r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.2.1:1234"
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("status: got %d, want 403", rec.Code)
		}
	})

	t.Run("client_ip_in_second_net_calls_next", func(t *testing.T) {
		r := gin.New()
		r.Use(ipWhitelistMiddleware([]*net.IPNet{net1, net2}))
		r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.10:1234"
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf(middlewareTestStatusOKFmt, rec.Code)
		}
	})

	t.Run("invalid_client_ip_returns_403", func(t *testing.T) {
		r := gin.New()
		r.Use(ipWhitelistMiddleware([]*net.IPNet{net1}))
		r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "not-an-ip"
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("status: got %d, want 403", rec.Code)
		}
	})
}
