package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/wg-keeper/wg-keeper-node/internal/wireguard"

	"github.com/gin-gonic/gin"
)

const (
	errMsgPeerIDMustBeUUIDv4 = "peerId must be uuid v4"
	maxPaginationLimit       = 1000
)

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
	c.JSON(http.StatusOK, HealthResponse{Status: "ok"})
}

// readinessHandler checks whether core WireGuard dependencies are healthy enough to serve traffic.
// Currently it treats successful Stats() call as readiness signal.
func readinessHandler(wgService statsProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, err := wgService.Stats(); err != nil {
			c.JSON(http.StatusServiceUnavailable, ReadinessResponse{
				Status: "unhealthy",
				Reason: "wireguard_unavailable",
			})
			return
		}
		c.JSON(http.StatusOK, ReadinessResponse{Status: "ok"})
	}
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
			// Do not log user-controlled data to avoid log injection.
			log.Printf("time=%s level=error msg=\"peer create failed\" reason=%s",
				time.Now().Format(time.RFC3339), reason)
			writeError(c, status, message, reason, debug, err)
			return
		}

		serverPublicKey, serverListenPort, err := wgService.ServerInfo()
		if err != nil {
			log.Printf("time=%s level=error msg=\"peer create failed\" reason=server_info_unavailable",
				time.Now().Format(time.RFC3339))
			writeError(c, http.StatusInternalServerError, "server public key unavailable", "server_info_unavailable", debug, err)
			return
		}

		log.Printf("time=%s level=info msg=\"peer created\"",
			time.Now().Format(time.RFC3339))
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
			// Do not log user-controlled data to avoid log injection.
			log.Printf("time=%s level=error msg=\"peer delete failed\" reason=%s",
				time.Now().Format(time.RFC3339), reason)
			writeError(c, status, message, reason, debug, err)
			return
		}

		log.Printf("time=%s level=info msg=\"peer deleted\"",
			time.Now().Format(time.RFC3339))
		c.JSON(http.StatusOK, DeletePeerResponse{Status: "ok"})
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
		total := len(list)
		if err := validatePaginationParams(c.Query("offset"), c.Query("limit")); err != nil {
			writeError(c, http.StatusBadRequest, err.Error(), "invalid_pagination", debug, nil)
			return
		}
		offset, limit, paginated := applyPagination(list, c.Query("offset"), c.Query("limit"))
		hasPrev := offset > 0 && total > 0
		hasNext := offset+len(paginated) < total
		var prevOffset, nextOffset *int
		if hasPrev {
			prev := offset - limit
			if prev < 0 {
				prev = 0
			}
			prevOffset = &prev
		}
		if hasNext {
			next := offset + limit
			nextOffset = &next
		}

		resp := Response[[]wireguard.PeerListItem]{
			Data: paginated,
			Meta: PaginationMeta{
				Offset:     offset,
				Limit:      limit,
				TotalItems: total,
				HasPrev:    hasPrev,
				HasNext:    hasNext,
				PrevOffset: prevOffset,
				NextOffset: nextOffset,
			},
		}

		c.JSON(http.StatusOK, resp)
	}
}

// validatePaginationParams returns an error if offset or limit are present but invalid.
// offset must be >= 0; limit must be between 1 and maxPaginationLimit.
func validatePaginationParams(offsetStr, limitStr string) error {
	if offsetStr != "" {
		n, err := strconv.Atoi(offsetStr)
		if err != nil || n < 0 {
			return fmt.Errorf("offset must be a non-negative integer")
		}
	}
	if limitStr != "" {
		n, err := strconv.Atoi(limitStr)
		if err != nil || n <= 0 || n > maxPaginationLimit {
			return fmt.Errorf("limit must be between 1 and %d", maxPaginationLimit)
		}
	}
	return nil
}

// applyPagination slices the list according to optional offset and limit query params.
// Params are assumed to be pre-validated by validatePaginationParams.
// It returns the resolved offset, limit, and the paginated slice.
func applyPagination(list []wireguard.PeerListItem, offsetStr, limitStr string) (offset int, limit int, paginated []wireguard.PeerListItem) {
	offset = 0
	if n, err := strconv.Atoi(offsetStr); err == nil && n >= 0 {
		offset = n
	}
	if offset >= len(list) {
		return offset, limit, []wireguard.PeerListItem{}
	}
	paginated = list[offset:]
	if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
		limit = n
		if limit < len(paginated) {
			paginated = paginated[:limit]
		}
	} else {
		limit = len(paginated)
	}
	return offset, limit, paginated
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
		c.JSON(http.StatusOK, detail)
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
