package wireguard

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestStoredToRecordAllowedIPs(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	stored := peerRecordStored{
		PeerID:     "peer-1",
		PublicKey:  key.String(),
		AllowedIPs: []string{"10.0.0.3/32", "fd00::3/128"},
		CreatedAt:  time.Now().UTC(),
	}
	rec, err := storedToRecord(stored)
	if err != nil {
		t.Fatalf("storedToRecord: %v", err)
	}
	if rec.PeerID != "peer-1" {
		t.Fatalf("peer_id: got %q", rec.PeerID)
	}
	if len(rec.AllowedIPs) != 2 {
		t.Fatalf("expected 2 allowed_ips, got %d", len(rec.AllowedIPs))
	}
	if rec.AllowedIPs[0].String() != "10.0.0.3/32" || rec.AllowedIPs[1].String() != "fd00::3/128" {
		t.Fatalf("allowed_ips: got %v", rec.AllowedIPs)
	}
}

func TestSaveToFileAndLoadFromFileRoundtrip(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	store := NewPeerStore()
	store.Set(PeerRecord{
		PeerID:     "roundtrip",
		PublicKey:  key,
		AllowedIPs: mustParseCIDRs(t, "10.0.0.1/32", "fd00::1/128"),
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  nil,
	})

	dir := t.TempDir()
	path := filepath.Join(dir, "peers.json")
	if err := store.SaveToFile(path); err != nil {
		t.Fatalf("SaveToFile: %v", err)
	}

	store2 := NewPeerStore()
	if err := store2.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	rec, ok := store2.Get("roundtrip")
	if !ok {
		t.Fatalf("expected record after roundtrip")
	}
	if rec.PublicKey != key {
		t.Fatalf("public_key changed after roundtrip")
	}
	if len(rec.AllowedIPs) != 2 {
		t.Fatalf("expected 2 allowed_ips, got %d", len(rec.AllowedIPs))
	}
}

func mustParseCIDRs(t *testing.T, cidrs ...string) []net.IPNet {
	t.Helper()
	out := make([]net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("parse %q: %v", c, err)
		}
		out = append(out, *n)
	}
	return out
}
