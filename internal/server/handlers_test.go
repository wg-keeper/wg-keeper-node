package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wg-keeper/wg-keeper-node/internal/wireguard"

	"github.com/gin-gonic/gin"
)

const (
	pathStats         = "/stats"
	pathPeers         = "/peers"
	pathPeersPeerID   = "/peers/:peerId"
	pathPeersTestUUID = "/peers/550e8400-e29b-41d4-a716-446655440000"
	testAllowedIP     = "10.0.0.2/32"
	testAPIKey        = "key"
	createPeerBody    = `{"peerId":"550e8400-e29b-41d4-a716-446655440000"}`
)

func newTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func assertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("expected status %d, got %d", want, rec.Code)
	}
}

func assertJSONErrorCode(t *testing.T, body []byte, wantCode string) {
	t.Helper()
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if got := payload["code"]; got != wantCode {
		t.Fatalf("expected code %q, got %v", wantCode, got)
	}
}

type mockWGService struct {
	statsFunc      func() (wireguard.Stats, error)
	ensurePeerFunc func(peerID string, expiresAt *time.Time) (wireguard.PeerInfo, error)
	deletePeerFunc func(string) error
	serverInfoFunc func() (string, int, error)
	listPeersFunc  func() ([]wireguard.PeerListItem, error)
	getPeerFunc    func(string) (*wireguard.PeerDetail, error)
}

func (m mockWGService) Stats() (wireguard.Stats, error) {
	return m.statsFunc()
}

func (m mockWGService) EnsurePeer(peerID string, expiresAt *time.Time) (wireguard.PeerInfo, error) {
	return m.ensurePeerFunc(peerID, expiresAt)
}

func (m mockWGService) DeletePeer(peerID string) error {
	return m.deletePeerFunc(peerID)
}

func (m mockWGService) ServerInfo() (string, int, error) {
	return m.serverInfoFunc()
}

func (m mockWGService) ListPeers() ([]wireguard.PeerListItem, error) {
	return m.listPeersFunc()
}

func (m mockWGService) GetPeer(peerID string) (*wireguard.PeerDetail, error) {
	return m.getPeerFunc(peerID)
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
	router := newTestRouter()
	router.GET(pathStats, apiKeyMiddleware(testAPIKey), statsHandler(mockWGService{
		statsFunc: func() (wireguard.Stats, error) {
			return wireguard.Stats{
				Service: wireguard.ServiceInfo{Name: "wg-keeper-node", Version: "0.0.1"},
			}, nil
		},
	}, false))

	rec := performRequest(t, router, http.MethodGet, pathStats, nil, testAPIKey)
	assertStatus(t, rec, http.StatusOK)
}

func TestStatsHandlerError(t *testing.T) {
	router := newTestRouter()
	router.GET(pathStats, apiKeyMiddleware(testAPIKey), statsHandler(mockWGService{
		statsFunc: func() (wireguard.Stats, error) {
			return wireguard.Stats{}, errors.New("boom")
		},
	}, false))

	rec := performRequest(t, router, http.MethodGet, pathStats, nil, testAPIKey)
	assertStatus(t, rec, http.StatusInternalServerError)
	assertJSONErrorCode(t, rec.Body.Bytes(), "stats_unavailable")
}

func TestCreatePeerInvalidJSON(t *testing.T) {
	router := newTestRouter()
	router.POST(pathPeers, apiKeyMiddleware(testAPIKey), createPeerHandler(mockWGService{}, false))

	rec := performRequest(t, router, http.MethodPost, pathPeers, []byte("{"), testAPIKey)
	assertStatus(t, rec, http.StatusBadRequest)
}

func TestCreatePeerInvalidPeerID(t *testing.T) {
	router := newTestRouter()
	router.POST(pathPeers, apiKeyMiddleware(testAPIKey), createPeerHandler(mockWGService{}, false))

	rec := performRequest(t, router, http.MethodPost, pathPeers, []byte(`{"peerId":"not-a-uuid-v4"}`), testAPIKey)
	assertStatus(t, rec, http.StatusBadRequest)
	assertJSONErrorCode(t, rec.Body.Bytes(), "invalid_peer_id")
}

func TestCreatePeerEnsureError(t *testing.T) {
	router := newTestRouter()
	router.POST(pathPeers, apiKeyMiddleware(testAPIKey), createPeerHandler(mockWGService{
		ensurePeerFunc: func(string, *time.Time) (wireguard.PeerInfo, error) {
			return wireguard.PeerInfo{}, wireguard.ErrNoAvailableIP
		},
	}, false))

	rec := performRequest(t, router, http.MethodPost, pathPeers, []byte(createPeerBody), testAPIKey)
	assertStatus(t, rec, http.StatusConflict)
}

func TestCreatePeerServerInfoError(t *testing.T) {
	router := newTestRouter()
	router.POST(pathPeers, apiKeyMiddleware(testAPIKey), createPeerHandler(mockWGService{
		ensurePeerFunc: func(string, *time.Time) (wireguard.PeerInfo, error) {
			return wireguard.PeerInfo{PeerID: "id"}, nil
		},
		serverInfoFunc: func() (string, int, error) {
			return "", 0, errors.New("boom")
		},
	}, false))

	rec := performRequest(t, router, http.MethodPost, pathPeers, []byte(createPeerBody), testAPIKey)
	assertStatus(t, rec, http.StatusInternalServerError)
}

func TestCreatePeerSuccess(t *testing.T) {
	router := newTestRouter()
	router.POST(pathPeers, apiKeyMiddleware(testAPIKey), createPeerHandler(mockWGService{
		ensurePeerFunc: func(string, *time.Time) (wireguard.PeerInfo, error) {
			return wireguard.PeerInfo{PeerID: "peer-1", PublicKey: "pub", PrivateKey: "priv", PresharedKey: "psk", AllowedIP: testAllowedIP}, nil
		},
		serverInfoFunc: func() (string, int, error) {
			return "server-pub", 51820, nil
		},
	}, false))

	rec := performRequest(t, router, http.MethodPost, pathPeers, []byte(createPeerBody), testAPIKey)
	assertStatus(t, rec, http.StatusOK)
}

func TestCreatePeerExpiresAtInPast(t *testing.T) {
	router := newTestRouter()
	router.POST(pathPeers, apiKeyMiddleware(testAPIKey), createPeerHandler(mockWGService{}, false))

	body := []byte(`{"peerId":"550e8400-e29b-41d4-a716-446655440000","expiresAt":"2020-01-01T00:00:00Z"}`)
	rec := performRequest(t, router, http.MethodPost, pathPeers, body, testAPIKey)
	assertStatus(t, rec, http.StatusBadRequest)
	assertJSONErrorCode(t, rec.Body.Bytes(), "invalid_expires_at")
}

func TestDeletePeerInvalidID(t *testing.T) {
	router := newTestRouter()
	router.DELETE(pathPeersPeerID, apiKeyMiddleware(testAPIKey), deletePeerHandler(mockWGService{}, false))

	rec := performRequest(t, router, http.MethodDelete, "/peers/not-a-uuid", nil, testAPIKey)
	assertStatus(t, rec, http.StatusBadRequest)
}

func TestDeletePeerNotFound(t *testing.T) {
	router := newTestRouter()
	router.DELETE(pathPeersPeerID, apiKeyMiddleware(testAPIKey), deletePeerHandler(mockWGService{
		deletePeerFunc: func(string) error {
			return wireguard.ErrPeerNotFound
		},
	}, false))

	rec := performRequest(t, router, http.MethodDelete, pathPeersTestUUID, nil, testAPIKey)
	assertStatus(t, rec, http.StatusNotFound)
}

func TestDeletePeerSuccess(t *testing.T) {
	router := newTestRouter()
	router.DELETE(pathPeersPeerID, apiKeyMiddleware(testAPIKey), deletePeerHandler(mockWGService{
		deletePeerFunc: func(string) error {
			return nil
		},
	}, false))

	rec := performRequest(t, router, http.MethodDelete, pathPeersTestUUID, nil, testAPIKey)
	assertStatus(t, rec, http.StatusOK)
}

func TestStatsHandlerErrorWithDebugDetail(t *testing.T) {
	router := newTestRouter()
	router.GET(pathStats, apiKeyMiddleware(testAPIKey), statsHandler(mockWGService{
		statsFunc: func() (wireguard.Stats, error) {
			return wireguard.Stats{}, errors.New("internal failure")
		},
	}, true))

	rec := performRequest(t, router, http.MethodGet, pathStats, nil, testAPIKey)
	assertStatus(t, rec, http.StatusInternalServerError)
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if payload["detail"] != "internal failure" {
		t.Fatalf("expected detail in debug mode, got %v", payload["detail"])
	}
}

func TestListPeersSuccess(t *testing.T) {
	router := newTestRouter()
	router.GET(pathPeers, apiKeyMiddleware(testAPIKey), listPeersHandler(mockWGService{
		listPeersFunc: func() ([]wireguard.PeerListItem, error) {
			return []wireguard.PeerListItem{
				{PeerID: "p1", AllowedIP: testAllowedIP, PublicKey: "pk1", Active: true, CreatedAt: "2025-01-01T00:00:00Z"},
			}, nil
		},
	}, false))

	rec := performRequest(t, router, http.MethodGet, pathPeers, nil, testAPIKey)
	assertStatus(t, rec, http.StatusOK)
	var payload struct {
		Peers []wireguard.PeerListItem `json:"peers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(payload.Peers) != 1 || payload.Peers[0].PeerID != "p1" {
		t.Fatalf("expected one peer p1, got %v", payload.Peers)
	}
}

func TestListPeersError(t *testing.T) {
	router := newTestRouter()
	router.GET(pathPeers, apiKeyMiddleware(testAPIKey), listPeersHandler(mockWGService{
		listPeersFunc: func() ([]wireguard.PeerListItem, error) {
			return nil, errors.New("device unavailable")
		},
	}, false))

	rec := performRequest(t, router, http.MethodGet, pathPeers, nil, testAPIKey)
	assertStatus(t, rec, http.StatusInternalServerError)
	assertJSONErrorCode(t, rec.Body.Bytes(), "peers_list_unavailable")
}

func TestListPeersUnauthorized(t *testing.T) {
	router := newTestRouter()
	router.GET(pathPeers, apiKeyMiddleware(testAPIKey), listPeersHandler(mockWGService{
		listPeersFunc: func() ([]wireguard.PeerListItem, error) { return nil, nil },
	}, false))

	rec := performRequest(t, router, http.MethodGet, pathPeers, nil, "")
	assertStatus(t, rec, http.StatusUnauthorized)
}

func TestGetPeerSuccess(t *testing.T) {
	router := newTestRouter()
	router.GET(pathPeersPeerID, apiKeyMiddleware(testAPIKey), getPeerHandler(mockWGService{
		getPeerFunc: func(peerID string) (*wireguard.PeerDetail, error) {
			return &wireguard.PeerDetail{
				PeerListItem:   wireguard.PeerListItem{PeerID: peerID, AllowedIP: testAllowedIP, PublicKey: "pk", Active: true, CreatedAt: "2025-01-01T00:00:00Z"},
				ReceiveBytes:   1000,
				TransmitBytes:  2000,
			}, nil
		},
	}, false))

	rec := performRequest(t, router, http.MethodGet, pathPeersTestUUID, nil, testAPIKey)
	assertStatus(t, rec, http.StatusOK)
	var payload struct {
		Peer wireguard.PeerDetail `json:"peer"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if payload.Peer.PeerID != "550e8400-e29b-41d4-a716-446655440000" || payload.Peer.ReceiveBytes != 1000 {
		t.Fatalf("unexpected peer in response: %+v", payload.Peer)
	}
}

func TestGetPeerNotFound(t *testing.T) {
	router := newTestRouter()
	router.GET(pathPeersPeerID, apiKeyMiddleware(testAPIKey), getPeerHandler(mockWGService{
		getPeerFunc: func(string) (*wireguard.PeerDetail, error) {
			return nil, wireguard.ErrPeerNotFound
		},
	}, false))

	rec := performRequest(t, router, http.MethodGet, pathPeersTestUUID, nil, testAPIKey)
	assertStatus(t, rec, http.StatusNotFound)
}

func TestGetPeerInvalidID(t *testing.T) {
	router := newTestRouter()
	router.GET(pathPeersPeerID, apiKeyMiddleware(testAPIKey), getPeerHandler(mockWGService{}, false))

	rec := performRequest(t, router, http.MethodGet, "/peers/not-a-uuid", nil, testAPIKey)
	assertStatus(t, rec, http.StatusBadRequest)
}

func TestGetPeerUnauthorized(t *testing.T) {
	router := newTestRouter()
	router.GET(pathPeersPeerID, apiKeyMiddleware(testAPIKey), getPeerHandler(mockWGService{
		getPeerFunc: func(string) (*wireguard.PeerDetail, error) { return nil, nil },
	}, false))

	rec := performRequest(t, router, http.MethodGet, pathPeersTestUUID, nil, "")
	assertStatus(t, rec, http.StatusUnauthorized)
}
