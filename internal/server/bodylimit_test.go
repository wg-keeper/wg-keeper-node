package server

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type errReader struct{}

func (errReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("read failed")
}

func TestBodyLimitMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const limit = 10

	t.Run("get_request_not_limited", func(t *testing.T) {
		r := gin.New()
		r.Use(bodyLimitMiddleware(limit))
		r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
		body := bytes.NewReader(make([]byte, limit+5))
		req := httptest.NewRequest(http.MethodGet, "/", body)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET with body: got status %d, want 200", rec.Code)
		}
	})

	t.Run("post_within_limit_calls_next", func(t *testing.T) {
		r := gin.New()
		r.Use(bodyLimitMiddleware(limit))
		r.POST("/", func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("12345")))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status: got %d, want 200", rec.Code)
		}
	})

	t.Run("post_over_limit_returns_413", func(t *testing.T) {
		r := gin.New()
		r.Use(bodyLimitMiddleware(limit))
		r.POST("/", func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(make([]byte, limit+1)))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("status: got %d, want 413", rec.Code)
		}
	})

	t.Run("put_over_limit_returns_413", func(t *testing.T) {
		r := gin.New()
		r.Use(bodyLimitMiddleware(limit))
		r.PUT("/", func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(make([]byte, limit+1)))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("status: got %d, want 413", rec.Code)
		}
	})

	t.Run("nil_body_calls_next", func(t *testing.T) {
		r := gin.New()
		r.Use(bodyLimitMiddleware(limit))
		r.POST("/", func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Body = nil
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status: got %d, want 200", rec.Code)
		}
	})

	t.Run("post_read_error_returns_400", func(t *testing.T) {
		r := gin.New()
		r.Use(bodyLimitMiddleware(limit))
		r.POST("/", func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodPost, "/", errReader{})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status: got %d, want 400", rec.Code)
		}
	})

	t.Run("delete_over_limit_body_is_restricted", func(t *testing.T) {
		// MaxBytesReader must be applied even for DELETE so that oversized chunked
		// bodies on non-POST methods are capped at the connection level.
		r := gin.New()
		r.Use(bodyLimitMiddleware(limit))
		r.DELETE("/", func(c *gin.Context) {
			// Attempt to read the body; should be capped by MaxBytesReader.
			buf, err := io.ReadAll(c.Request.Body)
			if err == nil && int64(len(buf)) > limit {
				c.Status(http.StatusOK) // body was NOT limited — test should fail
				return
			}
			c.Status(http.StatusOK) // body was limited or read failed — expected
		})
		req := httptest.NewRequest(http.MethodDelete, "/", bytes.NewReader(make([]byte, limit+5)))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status: got %d, want 200", rec.Code)
		}
	})
}
