package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wg-keeper/wg-keeper-node/internal/wireguard"

	"github.com/gin-gonic/gin"
)

const (
	pathStats         = "/stats"
	pathPeers         = "/peers"
	pathPeersPeerID   = "/peers/:peerId"
	msgExpected200Got = "expected 200, got %d"
	msgExpected500Got = "expected 500, got %d"
	msgInvalidJSON    = "invalid json: %v"
)

type mockWGService struct {
	statsFunc      func() (wireguard.Stats, error)
	ensurePeerFunc func(string) (wireguard.PeerInfo, error)
	deletePeerFunc func(string) error
	serverInfoFunc func() (string, int, error)
}

func (m mockWGService) Stats() (wireguard.Stats, error) {
	return m.statsFunc()
}

func (m mockWGService) EnsurePeer(peerID string) (wireguard.PeerInfo, error) {
	return m.ensurePeerFunc(peerID)
}

func (m mockWGService) DeletePeer(peerID string) error {
	return m.deletePeerFunc(peerID)
}

func (m mockWGService) ServerInfo() (string, int, error) {
	return m.serverInfoFunc()
}

func performRequest(t *testing.T, router *gin.Engine, method, path string, body []byte, apiKey string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestStatsHandlerSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET(pathStats, apiKeyMiddleware("key"), statsHandler(mockWGService{
		statsFunc: func() (wireguard.Stats, error) {
			return wireguard.Stats{
				Service: wireguard.ServiceInfo{Name: "wg-keeper-node", Version: "0.0.1"},
			}, nil
		},
	}, false))

	rec := performRequest(t, router, http.MethodGet, pathStats, nil, "key")
	if rec.Code != http.StatusOK {
		t.Fatalf(msgExpected200Got, rec.Code)
	}
}

func TestStatsHandlerError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET(pathStats, apiKeyMiddleware("key"), statsHandler(mockWGService{
		statsFunc: func() (wireguard.Stats, error) {
			return wireguard.Stats{}, errors.New("boom")
		},
	}, false))

	rec := performRequest(t, router, http.MethodGet, pathStats, nil, "key")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf(msgExpected500Got, rec.Code)
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf(msgInvalidJSON, err)
	}
	if payload["code"] != "stats_unavailable" {
		t.Fatalf("expected code stats_unavailable, got %q", payload["code"])
	}
}

func TestCreatePeerInvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST(pathPeers, apiKeyMiddleware("key"), createPeerHandler(mockWGService{}, false))

	rec := performRequest(t, router, http.MethodPost, pathPeers, []byte("{"), "key")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestCreatePeerInvalidPeerID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST(pathPeers, apiKeyMiddleware("key"), createPeerHandler(mockWGService{}, false))

	body := []byte(`{"peerId":"not-a-uuid-v4"}`)
	rec := performRequest(t, router, http.MethodPost, pathPeers, body, "key")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid peerId, got %d", rec.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf(msgInvalidJSON, err)
	}
	if payload["code"] != "invalid_peer_id" {
		t.Fatalf("expected code invalid_peer_id, got %v", payload["code"])
	}
}

func TestCreatePeerEnsureError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST(pathPeers, apiKeyMiddleware("key"), createPeerHandler(mockWGService{
		ensurePeerFunc: func(string) (wireguard.PeerInfo, error) {
			return wireguard.PeerInfo{}, wireguard.ErrNoAvailableIP
		},
	}, false))

	body := []byte(`{"peerId":"550e8400-e29b-41d4-a716-446655440000"}`)
	rec := performRequest(t, router, http.MethodPost, pathPeers, body, "key")
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}
}

func TestCreatePeerServerInfoError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST(pathPeers, apiKeyMiddleware("key"), createPeerHandler(mockWGService{
		ensurePeerFunc: func(string) (wireguard.PeerInfo, error) {
			return wireguard.PeerInfo{PeerID: "id"}, nil
		},
		serverInfoFunc: func() (string, int, error) {
			return "", 0, errors.New("boom")
		},
	}, false))

	body := []byte(`{"peerId":"550e8400-e29b-41d4-a716-446655440000"}`)
	rec := performRequest(t, router, http.MethodPost, pathPeers, body, "key")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf(msgExpected500Got, rec.Code)
	}
}

func TestCreatePeerSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST(pathPeers, apiKeyMiddleware("key"), createPeerHandler(mockWGService{
		ensurePeerFunc: func(string) (wireguard.PeerInfo, error) {
			return wireguard.PeerInfo{PeerID: "peer-1", PublicKey: "pub", PrivateKey: "priv", PresharedKey: "psk", AllowedIP: "10.0.0.2/32"}, nil
		},
		serverInfoFunc: func() (string, int, error) {
			return "server-pub", 51820, nil
		},
	}, false))

	body := []byte(`{"peerId":"550e8400-e29b-41d4-a716-446655440000"}`)
	rec := performRequest(t, router, http.MethodPost, pathPeers, body, "key")
	if rec.Code != http.StatusOK {
		t.Fatalf(msgExpected200Got, rec.Code)
	}
}

func TestDeletePeerInvalidID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.DELETE(pathPeersPeerID, apiKeyMiddleware("key"), deletePeerHandler(mockWGService{}, false))

	rec := performRequest(t, router, http.MethodDelete, "/peers/not-a-uuid", nil, "key")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestDeletePeerNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.DELETE(pathPeersPeerID, apiKeyMiddleware("key"), deletePeerHandler(mockWGService{
		deletePeerFunc: func(string) error {
			return wireguard.ErrPeerNotFound
		},
	}, false))

	rec := performRequest(t, router, http.MethodDelete, "/peers/550e8400-e29b-41d4-a716-446655440000", nil, "key")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestDeletePeerSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.DELETE(pathPeersPeerID, apiKeyMiddleware("key"), deletePeerHandler(mockWGService{
		deletePeerFunc: func(string) error {
			return nil
		},
	}, false))

	rec := performRequest(t, router, http.MethodDelete, "/peers/550e8400-e29b-41d4-a716-446655440000", nil, "key")
	if rec.Code != http.StatusOK {
		t.Fatalf(msgExpected200Got, rec.Code)
	}
}

func TestStatsHandlerErrorWithDebugDetail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET(pathStats, apiKeyMiddleware("key"), statsHandler(mockWGService{
		statsFunc: func() (wireguard.Stats, error) {
			return wireguard.Stats{}, errors.New("internal failure")
		},
	}, true))

	rec := performRequest(t, router, http.MethodGet, pathStats, nil, "key")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf(msgExpected500Got, rec.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf(msgInvalidJSON, err)
	}
	if payload["detail"] != "internal failure" {
		t.Fatalf("expected detail in debug mode, got %v", payload["detail"])
	}
}
