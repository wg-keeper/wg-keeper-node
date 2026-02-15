package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

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
		id := rec.Header().Get("X-Request-Id")
		if id == "" {
			t.Error("X-Request-Id header should be set")
		}
	})

	t.Run("reuses_id_from_header", func(t *testing.T) {
		wantID := "550e8400-e29b-41d4-a716-446655440000"
		req := httptest.NewRequest(http.MethodGet, "/id", nil)
		req.Header.Set("X-Request-Id", wantID)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if got := rec.Header().Get("X-Request-Id"); got != wantID {
			t.Errorf("X-Request-Id: got %q, want %q", got, wantID)
		}
	})
}

func TestGetRequestIDFromContext(t *testing.T) {
	ctx := context.Background()
	if got := GetRequestIDFromContext(ctx); got != "" {
		t.Errorf("empty context: got %q", got)
	}

	ctx = context.WithValue(ctx, struct{}{}, "not-string")
	if got := GetRequestIDFromContext(ctx); got != "" {
		t.Errorf("wrong type: got %q", got)
	}

	ctx = context.WithValue(ctx, requestIDCtxKey{}, "req-123")
	if got := GetRequestIDFromContext(ctx); got != "req-123" {
		t.Errorf("got %q, want req-123", got)
	}
}
