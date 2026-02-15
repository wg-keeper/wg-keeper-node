package wireguard

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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

func TestLoadFromFileIfExistsMissingFile(t *testing.T) {
	store := NewPeerStore()
	path := filepath.Join(t.TempDir(), "nonexistent.json")
	if err := store.LoadFromFileIfExists(path); err != nil {
		t.Fatalf("LoadFromFileIfExists(missing): expected nil, got %v", err)
	}
	if len(store.List()) != 0 {
		t.Fatalf("expected empty store after missing file, got %d", len(store.List()))
	}
}

func TestLoadFromFileIfExistsEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.json")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}
	store := NewPeerStore()
	if store.LoadFromFileIfExists(path) == nil {
		t.Fatal("LoadFromFileIfExists(empty file): expected error, got nil")
	}
}

func TestStoredToRecordEmptyPeerID(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	stored := peerRecordStored{
		PeerID:     "  ",
		PublicKey:  key.String(),
		AllowedIPs: []string{"10.0.0.1/32"},
		CreatedAt:  time.Now().UTC(),
	}
	_, err := storedToRecord(stored)
	if err == nil {
		t.Fatal("storedToRecord(empty peer_id): expected error, got nil")
	}
}

func TestStoredToRecordEmptyAllowedIPs(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	stored := peerRecordStored{
		PeerID:     "peer-1",
		PublicKey:  key.String(),
		AllowedIPs: []string{},
		CreatedAt:  time.Now().UTC(),
	}
	_, err := storedToRecord(stored)
	if err == nil {
		t.Fatal("storedToRecord(empty allowed_ips): expected error, got nil")
	}
}

func TestLoadFromDataNullRoot(t *testing.T) {
	store := NewPeerStore()
	err := store.loadFromData([]byte("null"))
	if err == nil {
		t.Fatal("loadFromData(null): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "must be a JSON array") {
		t.Errorf("expected error about JSON array, got: %v", err)
	}
}

func TestLoadFromDataDuplicatePublicKey(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	keyStr := key.String()
	data := []byte(fmt.Sprintf(`[
		{"peer_id":"a","public_key":%q,"allowed_ips":["10.0.0.1/32"],"created_at":"2024-01-01T00:00:00Z"},
		{"peer_id":"b","public_key":%q,"allowed_ips":["10.0.0.2/32"],"created_at":"2024-01-01T00:00:00Z"}
	]`, keyStr, keyStr))
	store := NewPeerStore()
	err := store.loadFromData(data)
	if err == nil {
		t.Fatal("loadFromData(duplicate public_key): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate public_key") {
		t.Errorf("expected error about duplicate public_key, got: %v", err)
	}
}
