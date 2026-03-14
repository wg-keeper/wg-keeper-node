package server

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wg-keeper/wg-keeper-node/internal/wireguard"
)

// silenceLogs redirects the standard logger to io.Discard for the duration of
// a benchmark and restores it afterwards. Use this for handlers that log on
// every request so that log I/O is not included in the measurement.
func silenceLogs(b *testing.B) {
	b.Helper()
	log.SetOutput(io.Discard)
	b.Cleanup(func() { log.SetOutput(os.Stderr) })
}

func init() {
	gin.SetMode(gin.TestMode)
}

func newBenchRouter(svc mockWGService) *gin.Engine {
	r := gin.New()
	r.POST("/peers", apiKeyMiddleware(testAPIKey), createPeerHandler(svc, false))
	r.GET("/peers", apiKeyMiddleware(testAPIKey), listPeersHandler(svc, false))
	r.GET("/peers/:peerId", apiKeyMiddleware(testAPIKey), getPeerHandler(svc, false))
	return r
}

func BenchmarkListPeersHandler(b *testing.B) {
	peers := make([]wireguard.PeerListItem, 100)
	for i := range peers {
		peers[i] = wireguard.PeerListItem{
			PeerID:          fmt.Sprintf("peer-%d", i),
			AllowedIPs:      []string{fmt.Sprintf("10.0.%d.2/32", i)},
			AddressFamilies: []string{"IPv4"},
			PublicKey:       "pk",
			CreatedAt:       time.Now().UTC().Format(time.RFC3339),
		}
	}
	svc := mockWGService{
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
	}
	router := newBenchRouter(svc)
	req := httptest.NewRequest(http.MethodGet, "/peers?limit=20", nil)
	req.Header.Set(apiKeyHeader, testAPIKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
	}
}

func BenchmarkCreatePeerHandler(b *testing.B) {
	silenceLogs(b)
	svc := mockWGService{
		ensurePeerFunc: func(_ string, _ *time.Time, _ []string) (wireguard.PeerInfo, error) {
			return wireguard.PeerInfo{
				PeerID:          "550e8400-e29b-41d4-a716-446655440000",
				PublicKey:       "pubkey",
				PrivateKey:      "privkey",
				PresharedKey:    "psk",
				AllowedIPs:      []string{"10.0.0.2/32"},
				AddressFamilies: []string{"IPv4"},
			}, nil
		},
		serverInfoFunc: func() (string, int, error) {
			return "serverpub", 51820, nil
		},
	}
	router := newBenchRouter(svc)
	body := []byte(`{"peerId":"550e8400-e29b-41d4-a716-446655440000"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/peers", bytes.NewReader(body))
		req.Header.Set(apiKeyHeader, testAPIKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
	}
}

func BenchmarkGetPeerHandler(b *testing.B) {
	detail := &wireguard.PeerDetail{
		PeerListItem: wireguard.PeerListItem{
			PeerID:          "550e8400-e29b-41d4-a716-446655440000",
			AllowedIPs:      []string{"10.0.0.2/32"},
			AddressFamilies: []string{"IPv4"},
			PublicKey:       "pk",
			CreatedAt:       time.Now().UTC().Format(time.RFC3339),
		},
		ReceiveBytes:  1024,
		TransmitBytes: 2048,
	}
	svc := mockWGService{
		getPeerFunc: func(_ string) (*wireguard.PeerDetail, error) { return detail, nil },
	}
	router := newBenchRouter(svc)
	req := httptest.NewRequest(http.MethodGet, "/peers/550e8400-e29b-41d4-a716-446655440000", nil)
	req.Header.Set(apiKeyHeader, testAPIKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
	}
}

func BenchmarkAPIKeyMiddleware(b *testing.B) {
	router := gin.New()
	router.GET("/", apiKeyMiddleware(testAPIKey), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(apiKeyHeader, testAPIKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
	}
}
