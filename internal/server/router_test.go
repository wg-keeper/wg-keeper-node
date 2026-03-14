package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wg-keeper/wg-keeper-node/internal/wireguard"
)

const routerTestAPIKey = "api-key"

func TestNewRouterHealth(t *testing.T) {
	svc := wireguard.NewTestService()
	router := NewRouter(context.Background(), routerTestAPIKey, nil, svc, false)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /healthz: got status %d", rec.Code)
	}
}

func TestNewRouterStatsWithAPIKey(t *testing.T) {
	svc := wireguard.NewTestService()
	router := NewRouter(context.Background(), routerTestAPIKey, nil, svc, false)
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	req.Header.Set("X-API-Key", routerTestAPIKey)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /stats with API key: got status %d", rec.Code)
	}
}

func TestNewRouterStatsWithoutAPIKey(t *testing.T) {
	svc := wireguard.NewTestService()
	router := NewRouter(context.Background(), routerTestAPIKey, nil, svc, false)
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /stats without API key: got status %d, want 401", rec.Code)
	}
}
