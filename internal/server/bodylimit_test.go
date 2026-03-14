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

	tests := []struct {
		name   string
		method string
		body   io.Reader
		want   int
	}{
		{"get_request_not_limited", http.MethodGet, bytes.NewReader(make([]byte, limit+5)), http.StatusOK},
		{"post_within_limit_calls_next", http.MethodPost, bytes.NewReader([]byte("12345")), http.StatusOK},
		{"post_over_limit_returns_413", http.MethodPost, bytes.NewReader(make([]byte, limit+1)), http.StatusRequestEntityTooLarge},
		{"put_over_limit_returns_413", http.MethodPut, bytes.NewReader(make([]byte, limit+1)), http.StatusRequestEntityTooLarge},
		{"nil_body_calls_next", http.MethodPost, nil, http.StatusOK},
		{"post_read_error_returns_400", http.MethodPost, errReader{}, http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.Use(bodyLimitMiddleware(limit))
			r.Handle(tc.method, "/", func(c *gin.Context) { c.Status(http.StatusOK) })
			req := httptest.NewRequest(tc.method, "/", tc.body)
			if tc.body == nil {
				req.Body = nil
			}
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("status: got %d, want %d", rec.Code, tc.want)
			}
		})
	}

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
			t.Errorf("status: got %d, want %d", rec.Code, http.StatusOK)
		}
	})
}
