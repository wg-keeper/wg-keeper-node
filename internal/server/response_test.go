package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/wg-keeper/wg-keeper-node/internal/wireguard"
)

func TestPaginationMetaJSON(t *testing.T) {
	prev := 0
	next := 10
	meta := PaginationMeta{
		Offset:     5,
		Limit:      5,
		TotalItems: 20,
		HasPrev:    true,
		HasNext:    true,
		PrevOffset: &prev,
		NextOffset: &next,
	}

	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal PaginationMeta: %v", err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal PaginationMeta JSON: %v", err)
	}

	if out["offset"] != float64(5) || out["limit"] != float64(5) || out["totalItems"] != float64(20) {
		t.Fatalf("unexpected numeric fields in PaginationMeta JSON: %v", out)
	}
}

func TestPeerListResponseJSON(t *testing.T) {
	now := time.Now().UTC()
	item := wireguard.PeerListItem{
		PeerID:          "peer-a",
		AllowedIPs:      []string{"10.0.0.2/32"},
		AddressFamilies: []string{wireguard.FamilyIPv4},
		PublicKey:       "pubkey",
		Active:          true,
		LastHandshakeAt: &now,
		CreatedAt:       now.Format(time.RFC3339),
	}

	resp := PeerListResponse{
		Data: []wireguard.PeerListItem{item},
		Meta: PaginationMeta{
			Offset:     0,
			Limit:      10,
			TotalItems: 1,
		},
	}

	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal PeerListResponse: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal PeerListResponse JSON: %v", err)
	}

	if _, ok := payload["data"]; !ok {
		t.Fatalf("expected data field in PeerListResponse JSON, got %v", payload)
	}
	if meta, ok := payload["meta"].(map[string]interface{}); !ok || meta["totalItems"] != float64(1) {
		t.Fatalf("expected meta.totalItems=1 in PeerListResponse JSON, got %v", payload["meta"])
	}
}

func TestHealthAndReadinessResponsesJSON(t *testing.T) {
	health := HealthResponse{Status: "ok"}
	if _, err := json.Marshal(health); err != nil {
		t.Fatalf("marshal HealthResponse: %v", err)
	}

	ready := ReadinessResponse{Status: "unhealthy", Reason: "wireguard_unavailable"}
	data, err := json.Marshal(ready)
	if err != nil {
		t.Fatalf("marshal ReadinessResponse: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal ReadinessResponse JSON: %v", err)
	}
	if out["status"] != "unhealthy" || out["reason"] != "wireguard_unavailable" {
		t.Fatalf("unexpected ReadinessResponse JSON: %v", out)
	}
}
