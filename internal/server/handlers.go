package server

import (
	"errors"
	"log"
	"net/http"

	"github.com/wg-keeper/wg-keeper-node/internal/wireguard"

	"github.com/gin-gonic/gin"
)

const errMsgPeerIDMustBeUUIDv4 = "peerId must be uuid v4"

type peerRequest struct {
	PeerID string `json:"peerId" binding:"required"`
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

		info, err := wgService.EnsurePeer(req.PeerID)
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
				PeerID:       info.PeerID,
				PublicKey:    info.PublicKey,
				PrivateKey:   info.PrivateKey,
				PresharedKey: info.PresharedKey,
				AllowedIP:    info.AllowedIP,
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

func peerError(err error) (int, string, string) {
	if errors.Is(err, wireguard.ErrPeerNotFound) {
		return http.StatusNotFound, "peer not found", "peer_not_found"
	}
	if errors.Is(err, wireguard.ErrNoAvailableIP) {
		return http.StatusConflict, "no available ip addresses", "no_available_ip"
	}

	return http.StatusInternalServerError, "wireguard operation failed", "wireguard_error"
}

func writeError(c *gin.Context, status int, message, code string, debug bool, err error) {
	out := gin.H{"error": message, "code": code}
	if debug && err != nil {
		out["detail"] = err.Error()
	}
	c.JSON(status, out)
}

type wgPeerService interface {
	EnsurePeer(string) (wireguard.PeerInfo, error)
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
