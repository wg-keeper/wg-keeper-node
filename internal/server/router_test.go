package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wg-keeper/wg-keeper-node/internal/wireguard"
)

const routerTestAPIKey = "api-key"

func TestNewRouterHealth(t *testing.T) {
	svc := wireguard.NewTestService()
	router := NewRouter(routerTestAPIKey, nil, svc, false)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /health: got status %d", rec.Code)
	}
}

func TestNewRouterStatsWithAPIKey(t *testing.T) {
	svc := wireguard.NewTestService()
	router := NewRouter(routerTestAPIKey, nil, svc, false)
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
	router := NewRouter(routerTestAPIKey, nil, svc, false)
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /stats without API key: got status %d, want 401", rec.Code)
	}
}
