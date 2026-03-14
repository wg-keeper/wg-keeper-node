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
	pathStats               = "/stats"
	pathPeers               = "/peers"
	pathPeersPeerID         = "/peers/:peerId"
	pathPeersTestUUID       = "/peers/550e8400-e29b-41d4-a716-446655440000"
	pathReadyz              = "/readyz"
	testAllowedIP           = "10.0.0.2/32"
	testAPIKey              = "key"
	createPeerBody          = `{"peerId":"550e8400-e29b-41d4-a716-446655440000"}`
	msgInvalidJSON          = "invalid json: %v"
	msgExpectedTotal10      = "expected total=10, got %v"
	errMsgDeviceUnavailable = "device unavailable"
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
		t.Fatalf(msgInvalidJSON, err)
	}
	if got := payload["code"]; got != wantCode {
		t.Fatalf("expected code %q, got %v", wantCode, got)
	}
}

type mockWGService struct {
	statsFunc      func() (wireguard.Stats, error)
	ensurePeerFunc func(peerID string, expiresAt *time.Time, addressFamilies []string) (wireguard.PeerInfo, error)
	deletePeerFunc func(string) error
	serverInfoFunc func() (string, int, error)
	listPeersFunc  func(offset, limit int) ([]wireguard.PeerListItem, int, error)
	getPeerFunc    func(string) (*wireguard.PeerDetail, error)
}

func (m mockWGService) Stats() (wireguard.Stats, error) {
	return m.statsFunc()
}

func (m mockWGService) EnsurePeer(peerID string, expiresAt *time.Time, addressFamilies []string) (wireguard.PeerInfo, error) {
	return m.ensurePeerFunc(peerID, expiresAt, addressFamilies)
}

func (m mockWGService) DeletePeer(peerID string) error {
	return m.deletePeerFunc(peerID)
}

func (m mockWGService) ServerInfo() (string, int, error) {
	return m.serverInfoFunc()
}

func (m mockWGService) ListPeers(offset, limit int) ([]wireguard.PeerListItem, int, error) {
	return m.listPeersFunc(offset, limit)
}

func (m mockWGService) GetPeer(peerID string) (*wireguard.PeerDetail, error) {
	return m.getPeerFunc(peerID)
}

func performRequest(t *testing.T, router *gin.Engine, method, path string, body []byte, apiKey string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if apiKey != "" {
		req.Header.Set(apiKeyHeader, apiKey)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestHealthHandler(t *testing.T) {
	router := newTestRouter()
	router.GET("/healthz", healthHandler)
	rec := performRequest(t, router, http.MethodGet, "/healthz", nil, "")
	assertStatus(t, rec, http.StatusOK)
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf(msgInvalidJSON, err)
	}
	if payload["status"] != "ok" {
		t.Errorf("expected status ok, got %v", payload["status"])
	}
}

func TestReadinessHandlerHealthy(t *testing.T) {
	router := newTestRouter()
	router.GET(pathReadyz, readinessHandler(mockWGService{
		statsFunc: func() (wireguard.Stats, error) {
			return wireguard.Stats{}, nil
		},
	}))

	rec := performRequest(t, router, http.MethodGet, pathReadyz, nil, "")
	assertStatus(t, rec, http.StatusOK)
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf(msgInvalidJSON, err)
	}
	if payload["status"] != "ok" {
		t.Errorf("expected status ok, got %v", payload["status"])
	}
}

func TestReadinessHandlerUnhealthy(t *testing.T) {
	router := newTestRouter()
	router.GET(pathReadyz, readinessHandler(mockWGService{
		statsFunc: func() (wireguard.Stats, error) {
			return wireguard.Stats{}, errors.New("wireguard down")
		},
	}))

	rec := performRequest(t, router, http.MethodGet, pathReadyz, nil, "")
	assertStatus(t, rec, http.StatusServiceUnavailable)
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf(msgInvalidJSON, err)
	}
	if payload["status"] != "unhealthy" || payload["reason"] != "wireguard_unavailable" {
		t.Fatalf("unexpected readiness payload: %v", payload)
	}
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
		ensurePeerFunc: func(string, *time.Time, []string) (wireguard.PeerInfo, error) {
			return wireguard.PeerInfo{}, wireguard.ErrNoAvailableIP
		},
	}, false))

	rec := performRequest(t, router, http.MethodPost, pathPeers, []byte(createPeerBody), testAPIKey)
	assertStatus(t, rec, http.StatusConflict)
}

func TestCreatePeerWireguardError(t *testing.T) {
	router := newTestRouter()
	router.POST(pathPeers, apiKeyMiddleware(testAPIKey), createPeerHandler(mockWGService{
		ensurePeerFunc: func(string, *time.Time, []string) (wireguard.PeerInfo, error) {
			return wireguard.PeerInfo{}, errors.New("device unavailable")
		},
	}, false))

	rec := performRequest(t, router, http.MethodPost, pathPeers, []byte(createPeerBody), testAPIKey)
	assertStatus(t, rec, http.StatusInternalServerError)
	assertJSONErrorCode(t, rec.Body.Bytes(), "wireguard_error")
}

func TestCreatePeerUnsupportedAddressFamily(t *testing.T) {
	router := newTestRouter()
	router.POST(pathPeers, apiKeyMiddleware(testAPIKey), createPeerHandler(mockWGService{
		ensurePeerFunc: func(string, *time.Time, []string) (wireguard.PeerInfo, error) {
			return wireguard.PeerInfo{}, wireguard.ErrUnsupportedAddressFamily
		},
	}, false))

	body := []byte(`{"peerId":"550e8400-e29b-41d4-a716-446655440000","addressFamilies":["IPv6"]}`)
	rec := performRequest(t, router, http.MethodPost, pathPeers, body, testAPIKey)
	assertStatus(t, rec, http.StatusBadRequest)
	assertJSONErrorCode(t, rec.Body.Bytes(), "unsupported_address_family")
}

func TestCreatePeerServerInfoError(t *testing.T) {
	router := newTestRouter()
	router.POST(pathPeers, apiKeyMiddleware(testAPIKey), createPeerHandler(mockWGService{
		ensurePeerFunc: func(string, *time.Time, []string) (wireguard.PeerInfo, error) {
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
		ensurePeerFunc: func(string, *time.Time, []string) (wireguard.PeerInfo, error) {
			return wireguard.PeerInfo{PeerID: "peer-1", PublicKey: "pub", PrivateKey: "priv", PresharedKey: "psk", AllowedIPs: []string{testAllowedIP}, AddressFamilies: []string{"IPv4"}}, nil
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

func TestCreatePeerExpiresAtInvalidFormat(t *testing.T) {
	router := newTestRouter()
	router.POST(pathPeers, apiKeyMiddleware(testAPIKey), createPeerHandler(mockWGService{}, false))

	body := []byte(`{"peerId":"550e8400-e29b-41d4-a716-446655440000","expiresAt":"not-a-date"}`)
	rec := performRequest(t, router, http.MethodPost, pathPeers, body, testAPIKey)
	assertStatus(t, rec, http.StatusBadRequest)
	assertJSONErrorCode(t, rec.Body.Bytes(), "invalid_expires_at")
}

func TestCreatePeerExpiresAtFuture(t *testing.T) {
	router := newTestRouter()
	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	router.POST(pathPeers, apiKeyMiddleware(testAPIKey), createPeerHandler(mockWGService{
		ensurePeerFunc: func(string, *time.Time, []string) (wireguard.PeerInfo, error) {
			return wireguard.PeerInfo{PeerID: "p1", PublicKey: "pk", PrivateKey: "sk", PresharedKey: "psk", AllowedIPs: []string{testAllowedIP}, AddressFamilies: []string{"IPv4"}}, nil
		},
		serverInfoFunc: func() (string, int, error) { return "spub", 51820, nil },
	}, false))

	body := []byte(`{"peerId":"550e8400-e29b-41d4-a716-446655440000","expiresAt":"` + future + `"}`)
	rec := performRequest(t, router, http.MethodPost, pathPeers, body, testAPIKey)
	assertStatus(t, rec, http.StatusOK)
}

func TestGetPeerWireguardError(t *testing.T) {
	router := newTestRouter()
	router.GET(pathPeersPeerID, apiKeyMiddleware(testAPIKey), getPeerHandler(mockWGService{
		getPeerFunc: func(string) (*wireguard.PeerDetail, error) {
			return nil, errors.New(errMsgDeviceUnavailable)
		},
	}, false))

	rec := performRequest(t, router, http.MethodGet, pathPeersTestUUID, nil, testAPIKey)
	assertStatus(t, rec, http.StatusInternalServerError)
	assertJSONErrorCode(t, rec.Body.Bytes(), "wireguard_error")
}

func TestBodyLimitTooLarge(t *testing.T) {
	router := newTestRouter()
	router.Use(bodyLimitMiddleware(MaxRequestBodySize))
	router.POST(pathPeers, apiKeyMiddleware(testAPIKey), createPeerHandler(mockWGService{}, false))

	body := make([]byte, MaxRequestBodySize+1)
	rec := performRequest(t, router, http.MethodPost, pathPeers, body, testAPIKey)
	assertStatus(t, rec, http.StatusRequestEntityTooLarge)
	assertJSONErrorCode(t, rec.Body.Bytes(), "body_too_large")
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

func TestDeletePeerWireguardError(t *testing.T) {
	router := newTestRouter()
	router.DELETE(pathPeersPeerID, apiKeyMiddleware(testAPIKey), deletePeerHandler(mockWGService{
		deletePeerFunc: func(string) error {
			return errors.New("device busy")
		},
	}, false))

	rec := performRequest(t, router, http.MethodDelete, pathPeersTestUUID, nil, testAPIKey)
	assertStatus(t, rec, http.StatusInternalServerError)
	assertJSONErrorCode(t, rec.Body.Bytes(), "wireguard_error")
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
		t.Fatalf(msgInvalidJSON, err)
	}
	if payload["detail"] != "internal failure" {
		t.Fatalf("expected detail in debug mode, got %v", payload["detail"])
	}
}

func TestListPeersSuccess(t *testing.T) {
	router := newTestRouter()
	router.GET(pathPeers, apiKeyMiddleware(testAPIKey), listPeersHandler(mockWGService{
		listPeersFunc: func(_, _ int) ([]wireguard.PeerListItem, int, error) {
			return []wireguard.PeerListItem{
				{PeerID: "p1", AllowedIPs: []string{testAllowedIP}, AddressFamilies: []string{"IPv4"}, PublicKey: "pk1", Active: true, CreatedAt: "2025-01-01T00:00:00Z"},
			}, 1, nil
		},
	}, false))

	rec := performRequest(t, router, http.MethodGet, pathPeers, nil, testAPIKey)
	assertStatus(t, rec, http.StatusOK)
	var payload struct {
		Data []wireguard.PeerListItem `json:"data"`
		Meta PaginationMeta           `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf(msgInvalidJSON, err)
	}
	if len(payload.Data) != 1 || payload.Data[0].PeerID != "p1" {
		t.Fatalf("expected one peer p1, got %v", payload.Data)
	}
}

func TestListPeersNilListReturnsEmpty(t *testing.T) {
	router := newTestRouter()
	router.GET(pathPeers, apiKeyMiddleware(testAPIKey), listPeersHandler(mockWGService{
		listPeersFunc: func(_, _ int) ([]wireguard.PeerListItem, int, error) {
			return nil, 0, nil
		},
	}, false))

	rec := performRequest(t, router, http.MethodGet, pathPeers, nil, testAPIKey)
	assertStatus(t, rec, http.StatusOK)
	var payload struct {
		Data []wireguard.PeerListItem `json:"data"`
		Meta PaginationMeta           `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf(msgInvalidJSON, err)
	}
	if payload.Data == nil || len(payload.Data) != 0 {
		t.Fatalf("expected empty peers array, got %v", payload.Data)
	}
}

func TestListPeersError(t *testing.T) {
	router := newTestRouter()
	router.GET(pathPeers, apiKeyMiddleware(testAPIKey), listPeersHandler(mockWGService{
		listPeersFunc: func(_, _ int) ([]wireguard.PeerListItem, int, error) {
			return nil, 0, errors.New(errMsgDeviceUnavailable)
		},
	}, false))

	rec := performRequest(t, router, http.MethodGet, pathPeers, nil, testAPIKey)
	assertStatus(t, rec, http.StatusInternalServerError)
	assertJSONErrorCode(t, rec.Body.Bytes(), "peers_list_unavailable")
}

func TestListPeersUnauthorized(t *testing.T) {
	router := newTestRouter()
	router.GET(pathPeers, apiKeyMiddleware(testAPIKey), listPeersHandler(mockWGService{
		listPeersFunc: func(_, _ int) ([]wireguard.PeerListItem, int, error) { return nil, 0, nil },
	}, false))

	rec := performRequest(t, router, http.MethodGet, pathPeers, nil, "")
	assertStatus(t, rec, http.StatusUnauthorized)
}

func TestGetPeerSuccess(t *testing.T) {
	router := newTestRouter()
	router.GET(pathPeersPeerID, apiKeyMiddleware(testAPIKey), getPeerHandler(mockWGService{
		getPeerFunc: func(peerID string) (*wireguard.PeerDetail, error) {
			return &wireguard.PeerDetail{
				PeerListItem:  wireguard.PeerListItem{PeerID: peerID, AllowedIPs: []string{testAllowedIP}, AddressFamilies: []string{"IPv4"}, PublicKey: "pk", Active: true, CreatedAt: "2025-01-01T00:00:00Z"},
				ReceiveBytes:  1000,
				TransmitBytes: 2000,
			}, nil
		},
	}, false))

	rec := performRequest(t, router, http.MethodGet, pathPeersTestUUID, nil, testAPIKey)
	assertStatus(t, rec, http.StatusOK)
	var payload wireguard.PeerDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf(msgInvalidJSON, err)
	}
	if payload.PeerID != "550e8400-e29b-41d4-a716-446655440000" || payload.ReceiveBytes != 1000 {
		t.Fatalf("unexpected peer in response: %+v", payload)
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

// ---------- pagination tests ----------

func makePeerList(n int) []wireguard.PeerListItem {
	peers := make([]wireguard.PeerListItem, n)
	for i := range peers {
		peers[i] = wireguard.PeerListItem{PeerID: "peer-" + string(rune('a'+i))}
	}
	return peers
}

func listPeersWithPagination(t *testing.T, peers []wireguard.PeerListItem, query string) (list []interface{}, total float64, meta map[string]interface{}) {
	t.Helper()
	router := newTestRouter()
	router.GET(pathPeers, apiKeyMiddleware(testAPIKey), listPeersHandler(mockWGService{
		listPeersFunc: func(offset, limit int) ([]wireguard.PeerListItem, int, error) {
			total := len(peers)
			if offset >= total {
				return []wireguard.PeerListItem{}, total, nil
			}
			result := peers[offset:]
			if limit > 0 && limit < len(result) {
				result = result[:limit]
			}
			return result, total, nil
		},
	}, false))

	rec := performRequest(t, router, http.MethodGet, pathPeers+query, nil, testAPIKey)
	assertStatus(t, rec, http.StatusOK)
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf(msgInvalidJSON, err)
	}
	rawPeers, _ := payload["data"].([]interface{})
	meta, _ = payload["meta"].(map[string]interface{})
	if meta != nil {
		if v, ok := meta["totalItems"].(float64); ok {
			total = v
		}
	}
	return rawPeers, total, meta
}

func TestListPeersResponseIncludesTotal(t *testing.T) {
	peers := makePeerList(5)
	list, total, meta := listPeersWithPagination(t, peers, "")
	if total != 5 {
		t.Errorf("expected total=5, got %v", total)
	}
	if len(list) != 5 {
		t.Errorf("expected 5 peers returned, got %d", len(list))
	}
	if meta == nil {
		t.Fatal("expected meta object, got nil")
	}
	if offset, _ := meta["offset"].(float64); offset != 0 {
		t.Errorf("expected offset=0, got %v", offset)
	}
}

func TestListPeersLimit(t *testing.T) {
	peers := makePeerList(10)
	list, total, meta := listPeersWithPagination(t, peers, "?limit=3")
	if total != 10 {
		t.Errorf(msgExpectedTotal10, total)
	}
	if len(list) != 3 {
		t.Errorf("expected 3 peers with limit=3, got %d", len(list))
	}
	if limit, _ := meta["limit"].(float64); limit != 3 {
		t.Errorf("expected limit=3 in meta, got %v", limit)
	}
	if hasNext, _ := meta["hasNext"].(bool); !hasNext {
		t.Errorf("expected hasNext=true for 10 total and limit=3")
	}
}

func TestListPeersOffset(t *testing.T) {
	peers := makePeerList(10)
	list, total, meta := listPeersWithPagination(t, peers, "?offset=7")
	if total != 10 {
		t.Errorf(msgExpectedTotal10, total)
	}
	if len(list) != 3 {
		t.Errorf("expected 3 peers after offset=7 of 10, got %d", len(list))
	}
	if offset, _ := meta["offset"].(float64); offset != 7 {
		t.Errorf("expected offset=7 in meta, got %v", offset)
	}
	if hasPrev, _ := meta["hasPrev"].(bool); !hasPrev {
		t.Errorf("expected hasPrev=true when offset>0")
	}
}

func TestListPeersOffsetAndLimit(t *testing.T) {
	peers := makePeerList(10)
	list, total, meta := listPeersWithPagination(t, peers, "?offset=2&limit=4")
	if total != 10 {
		t.Errorf(msgExpectedTotal10, total)
	}
	if len(list) != 4 {
		t.Errorf("expected 4 peers (offset=2, limit=4), got %d", len(list))
	}
	if offset, _ := meta["offset"].(float64); offset != 2 {
		t.Errorf("expected offset=2 in meta, got %v", offset)
	}
	if limit, _ := meta["limit"].(float64); limit != 4 {
		t.Errorf("expected limit=4 in meta, got %v", limit)
	}
}

func TestListPeersOffsetBeyondTotal(t *testing.T) {
	peers := makePeerList(5)
	list, total, meta := listPeersWithPagination(t, peers, "?offset=100")
	if total != 5 {
		t.Errorf("expected total=5, got %v", total)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 peers when offset > total, got %d", len(list))
	}
	if hasNext, _ := meta["hasNext"].(bool); hasNext {
		t.Errorf("expected hasNext=false when page is empty")
	}
}

func TestListPeersInvalidParamsRejected(t *testing.T) {
	peers := makePeerList(5)
	router := newTestRouter()
	router.GET(pathPeers, apiKeyMiddleware(testAPIKey), listPeersHandler(mockWGService{
		listPeersFunc: func(_, _ int) ([]wireguard.PeerListItem, int, error) { return peers, len(peers), nil },
	}, false))

	cases := []string{
		"?offset=abc",
		"?limit=xyz",
		"?offset=-1",
		"?limit=0",
		"?limit=-5",
	}
	for _, q := range cases {
		rec := performRequest(t, router, http.MethodGet, pathPeers+q, nil, testAPIKey)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("query %q: expected 400, got %d", q, rec.Code)
		}
	}
}

func TestParseExpiresAtNil(t *testing.T) {
	got, err := parseExpiresAt(nil)
	if err != nil || got != nil {
		t.Errorf("expected (nil, nil), got (%v, %v)", got, err)
	}
}

func TestParseExpiresAtEmptyString(t *testing.T) {
	empty := ""
	got, err := parseExpiresAt(&empty)
	if err != nil || got != nil {
		t.Errorf("expected (nil, nil), got (%v, %v)", got, err)
	}
}

func TestListPeersLimitLargerThanTotal(t *testing.T) {
	peers := makePeerList(3)
	list, _, meta := listPeersWithPagination(t, peers, "?limit=100")
	if len(list) != 3 {
		t.Errorf("expected 3 peers when limit > total, got %d", len(list))
	}
	if limit, _ := meta["limit"].(float64); limit != 100 {
		t.Errorf("expected limit=100 (requested), got %v", limit)
	}
}
