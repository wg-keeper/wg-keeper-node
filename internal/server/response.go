package server

import "github.com/wg-keeper/wg-keeper-node/internal/wireguard"

// PaginationMeta describes offset-based pagination metadata for list responses.
type PaginationMeta struct {
	Offset     int  `json:"offset"`
	Limit      int  `json:"limit"`
	TotalItems int  `json:"totalItems"`
	HasPrev    bool `json:"hasPrev"`
	HasNext    bool `json:"hasNext"`
	PrevOffset *int `json:"prevOffset,omitempty"`
	NextOffset *int `json:"nextOffset,omitempty"`
}

// Response is a generic API response envelope with a typed data payload and optional metadata.
type Response[T any] struct {
	Data T              `json:"data"`
	Meta PaginationMeta `json:"meta,omitempty"`
}

// PeerListResponse is the envelope for paginated peer list responses.
type PeerListResponse = Response[[]wireguard.PeerListItem]

// StatsResponse is the envelope for stats responses.
type StatsResponse = Response[wireguard.Stats]

// HealthResponse is returned by the health check endpoint.
type HealthResponse struct {
	Status string `json:"status"`
}

// ReadinessResponse is returned by the readiness endpoint.
type ReadinessResponse struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// DeletePeerResponse is returned when a peer is successfully deleted.
type DeletePeerResponse struct {
	Status string `json:"status"`
}

// PeerDetailResponse wraps a single peer detail.
type PeerDetailResponse struct {
	Peer *wireguard.PeerDetail `json:"peer"`
}

// CreatePeerResponseEnvelope is the envelope for successful peer creation.
// createPeerResponse is defined in handlers.go in the same package.
type CreatePeerResponseEnvelope = Response[createPeerResponse]
