package server

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/wg-keeper/wg-keeper-node/internal/wireguard"

	"github.com/gin-gonic/gin"
)

const errMsgPeerIDMustBeUUIDv4 = "peerId must be uuid v4"

type peerRequest struct {
	PeerID          string   `json:"peerId" binding:"required"`
	ExpiresAt       *string  `json:"expiresAt,omitempty"`       // RFC3339; omit = permanent peer
	AddressFamilies []string `json:"addressFamilies,omitempty"` // optional: ["IPv4"], ["IPv6"], or ["IPv4","IPv6"]; omit = all node supports
}

type peerResponse struct {
	PeerID          string   `json:"peerId"`
	PublicKey       string   `json:"publicKey"`
	PrivateKey      string   `json:"privateKey"`
	PresharedKey    string   `json:"presharedKey"`
	AllowedIPs      []string `json:"allowedIPs"`
	AddressFamilies []string `json:"addressFamilies"`
}

type serverInfoResponse struct {
	PublicKey  string `json:"publicKey"`
	ListenPort int    `json:"listenPort"`
}

type createPeerResponse struct {
	Server serverInfoResponse `json:"server"`
	Peer   peerResponse       `json:"peer"`
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func statsHandler(wgService statsProvider, debug bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		stats, err := wgService.Stats()
		if err != nil {
			writeError(c, http.StatusInternalServerError, "stats unavailable", "stats_unavailable", debug, err)
			return
		}

		c.JSON(http.StatusOK, stats)
	}
}

func createPeerHandler(wgService wgPeerService, debug bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req peerRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			writeError(c, http.StatusBadRequest, "invalid json body", "invalid_json", debug, err)
			return
		}
		if !IsUUIDv4(req.PeerID) {
			writeError(c, http.StatusBadRequest, errMsgPeerIDMustBeUUIDv4, "invalid_peer_id", debug, nil)
			return
		}
		expiresAt, err := parseExpiresAt(req.ExpiresAt)
		if err != nil {
			writeError(c, http.StatusBadRequest, err.Error(), "invalid_expires_at", debug, err)
			return
		}

		info, err := wgService.EnsurePeer(req.PeerID, expiresAt, req.AddressFamilies)
		if err != nil {
			status, message, reason := peerError(err)
			log.Printf("peer create failed: reason=%s", reason)
			writeError(c, status, message, reason, debug, err)
			return
		}

		serverPublicKey, serverListenPort, err := wgService.ServerInfo()
		if err != nil {
			log.Printf("peer create failed: reason=server_info_unavailable")
			writeError(c, http.StatusInternalServerError, "server public key unavailable", "server_info_unavailable", debug, err)
			return
		}

		log.Printf("peer created")
		c.JSON(http.StatusOK, createPeerResponse{
			Server: serverInfoResponse{
				PublicKey:  serverPublicKey,
				ListenPort: serverListenPort,
			},
			Peer: peerResponse{
				PeerID:          info.PeerID,
				PublicKey:       info.PublicKey,
				PrivateKey:      info.PrivateKey,
				PresharedKey:    info.PresharedKey,
				AllowedIPs:      info.AllowedIPs,
				AddressFamilies: info.AddressFamilies,
			},
		})
	}
}

func deletePeerHandler(wgService wgPeerService, debug bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		peerID := c.Param("peerId")
		if !IsUUIDv4(peerID) {
			writeError(c, http.StatusBadRequest, errMsgPeerIDMustBeUUIDv4, "invalid_peer_id", debug, nil)
			return
		}

		if err := wgService.DeletePeer(peerID); err != nil {
			status, message, reason := peerError(err)
			log.Printf("peer delete failed: reason=%s", reason)
			writeError(c, status, message, reason, debug, err)
			return
		}

		log.Printf("peer deleted")
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

func listPeersHandler(wgService wgPeersListProvider, debug bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		list, err := wgService.ListPeers()
		if err != nil {
			writeError(c, http.StatusInternalServerError, "peers list unavailable", "peers_list_unavailable", debug, err)
			return
		}
		if list == nil {
			list = []wireguard.PeerListItem{}
		}
		c.JSON(http.StatusOK, gin.H{"peers": list})
	}
}

func getPeerHandler(wgService wgPeerDetailProvider, debug bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		peerID := c.Param("peerId")
		if !IsUUIDv4(peerID) {
			writeError(c, http.StatusBadRequest, errMsgPeerIDMustBeUUIDv4, "invalid_peer_id", debug, nil)
			return
		}
		detail, err := wgService.GetPeer(peerID)
		if err != nil {
			status, message, reason := peerError(err)
			writeError(c, status, message, reason, debug, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"peer": detail})
	}
}

// parseExpiresAt parses optional RFC3339 date. If nil or empty, returns (nil, nil).
// If provided, must be in the future; otherwise returns error.
func parseExpiresAt(s *string) (*time.Time, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil, errors.New("expiresAt must be RFC3339")
	}
	utc := t.UTC()
	now := time.Now().UTC()
	if !utc.After(now) {
		return nil, errors.New("expiresAt must be in the future")
	}
	return &utc, nil
}

func peerError(err error) (int, string, string) {
	if errors.Is(err, wireguard.ErrPeerNotFound) {
		return http.StatusNotFound, "peer not found", "peer_not_found"
	}
	if errors.Is(err, wireguard.ErrNoAvailableIP) {
		return http.StatusConflict, "no available ip addresses", "no_available_ip"
	}
	if errors.Is(err, wireguard.ErrUnsupportedAddressFamily) {
		return http.StatusBadRequest, "requested address family is not supported by this node", "unsupported_address_family"
	}

	return http.StatusInternalServerError, "wireguard operation failed", "wireguard_error"
}

// writeError sends a JSON error. When debug is true, err.Error() is included as "detail"; set debug=false in production to avoid leaking internal details.
func writeError(c *gin.Context, status int, message, code string, debug bool, err error) {
	out := gin.H{"error": message, "code": code}
	if debug && err != nil {
		out["detail"] = err.Error()
	}
	c.JSON(status, out)
}

type wgPeerService interface {
	EnsurePeer(peerID string, expiresAt *time.Time, addressFamilies []string) (wireguard.PeerInfo, error)
	DeletePeer(string) error
	ServerInfo() (string, int, error)
}

// statsProvider provides WireGuard stats (single-method interface naming).
type statsProvider interface {
	Stats() (wireguard.Stats, error)
}

type wgPeersListProvider interface {
	ListPeers() ([]wireguard.PeerListItem, error)
}

type wgPeerDetailProvider interface {
	GetPeer(string) (*wireguard.PeerDetail, error)
}
