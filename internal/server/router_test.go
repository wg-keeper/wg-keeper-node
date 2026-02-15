package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wg-keeper/wg-keeper-node/internal/wireguard"
)

func TestNewRouter_Health(t *testing.T) {
	svc := wireguard.NewTestService()
	router := NewRouter("api-key", nil, svc, false)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /health: got status %d", rec.Code)
	}
}

func TestNewRouter_StatsWithAPIKey(t *testing.T) {
	svc := wireguard.NewTestService()
	router := NewRouter("api-key", nil, svc, false)
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	req.Header.Set("X-API-Key", "api-key")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /stats with API key: got status %d", rec.Code)
	}
}

func TestNewRouter_StatsWithoutAPIKey(t *testing.T) {
	svc := wireguard.NewTestService()
	router := NewRouter("api-key", nil, svc, false)
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /stats without API key: got status %d, want 401", rec.Code)
	}
}
