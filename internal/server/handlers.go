package server

import (
	"errors"
	"log"
	"net/http"

	"github.com/wg-keeper/wg-keeper-node/internal/wireguard"

	"github.com/gin-gonic/gin"
)

type peerRequest struct {
	PeerID string `json:"peerId" binding:"required,uuid4"`
}

type peerResponse struct {
	PeerID       string `json:"peerId"`
	PublicKey    string `json:"publicKey"`
	PrivateKey   string `json:"privateKey"`
	PresharedKey string `json:"presharedKey"`
	AllowedIP    string `json:"allowedIp"`
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

func statsHandler(wgService wgStatsService) gin.HandlerFunc {
	return func(c *gin.Context) {
		stats, err := wgService.Stats()
		if err != nil {
			writeError(c, http.StatusInternalServerError, "stats unavailable", "stats_unavailable")
			return
		}

		c.JSON(http.StatusOK, stats)
	}
}

func createPeerHandler(wgService wgPeerService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req peerRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			writeError(c, http.StatusBadRequest, "invalid json body", "invalid_json")
			return
		}

		info, err := wgService.EnsurePeer(req.PeerID)
		if err != nil {
			status, message, reason := peerError(err)
			log.Printf("peer create failed: peerId=%s reason=%s", req.PeerID, reason)
			c.JSON(status, gin.H{"error": message})
			return
		}

		serverPublicKey, serverListenPort, err := wgService.ServerInfo()
		if err != nil {
			log.Printf("peer create failed: peerId=%s reason=server_info_unavailable", req.PeerID)
			writeError(c, http.StatusInternalServerError, "server public key unavailable", "server_info_unavailable")
			return
		}

		log.Printf("peer created: %s", info.PeerID)
		c.JSON(http.StatusOK, createPeerResponse{
			Server: serverInfoResponse{
				PublicKey:  serverPublicKey,
				ListenPort: serverListenPort,
			},
			Peer: peerResponse{
				PeerID:       info.PeerID,
				PublicKey:    info.PublicKey,
				PrivateKey:   info.PrivateKey,
				PresharedKey: info.PresharedKey,
				AllowedIP:    info.AllowedIP,
			},
		})
	}
}

func deletePeerHandler(wgService wgPeerService) gin.HandlerFunc {
	return func(c *gin.Context) {
		peerID := c.Param("peerId")
		if !isUUIDv4(peerID) {
			writeError(c, http.StatusBadRequest, "peerId must be uuid v4", "invalid_peer_id")
			return
		}

		if err := wgService.DeletePeer(peerID); err != nil {
			status, message, reason := peerError(err)
			log.Printf("peer delete failed: peerId=%s reason=%s", peerID, reason)
			c.JSON(status, gin.H{"error": message})
			return
		}

		log.Printf("peer deleted: %s", peerID)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

func peerError(err error) (int, string, string) {
	if errors.Is(err, wireguard.ErrPeerNotFound) {
		return http.StatusNotFound, "peer not found", "peer_not_found"
	}
	if errors.Is(err, wireguard.ErrNoAvailableIP) {
		return http.StatusConflict, "no available ip addresses", "no_available_ip"
	}

	return http.StatusInternalServerError, "wireguard operation failed", "wireguard_error"
}

func writeError(c *gin.Context, status int, message, code string) {
	c.JSON(status, gin.H{"error": message, "code": code})
}

type wgPeerService interface {
	EnsurePeer(string) (wireguard.PeerInfo, error)
	DeletePeer(string) error
	ServerInfo() (string, int, error)
}

type wgStatsService interface {
	Stats() (wireguard.Stats, error)
}
