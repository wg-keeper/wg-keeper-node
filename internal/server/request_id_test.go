package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// testWrongCtxKey is a distinct type used as context key to test GetRequestIDFromContext ignores other keys.
type testWrongCtxKey struct{}

func TestRequestIDMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(requestIDMiddleware())
	r.GET("/id", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"id": GetRequestID(c)})
	})

	t.Run("generates_id_when_missing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/id", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d", rec.Code)
		}
		id := rec.Header().Get(requestIDHeader)
		if id == "" {
			t.Error(requestIDHeader + " header should be set")
		}
	})

	t.Run("reuses_id_from_header", func(t *testing.T) {
		wantID := "550e8400-e29b-41d4-a716-446655440000"
		req := httptest.NewRequest(http.MethodGet, "/id", nil)
		req.Header.Set(requestIDHeader, wantID)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if got := rec.Header().Get(requestIDHeader); got != wantID {
			t.Errorf("%s: got %q, want %q", requestIDHeader, got, wantID)
		}
	})
}

func TestGetRequestIDFromContext(t *testing.T) {
	ctx := context.Background()
	if got := GetRequestIDFromContext(ctx); got != "" {
		t.Errorf("empty context: got %q", got)
	}

	ctx = context.WithValue(ctx, testWrongCtxKey{}, "not-string")
	if got := GetRequestIDFromContext(ctx); got != "" {
		t.Errorf("wrong type: got %q", got)
	}

	ctx = context.WithValue(ctx, requestIDCtxKey{}, "req-123")
	if got := GetRequestIDFromContext(ctx); got != "req-123" {
		t.Errorf("got %q, want req-123", got)
	}
}
