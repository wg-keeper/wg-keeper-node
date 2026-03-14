package wireguard

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	testAllowedIP = "10.0.0.1/32"
	testPeersFile = "peers.json"
)

func makeStorePeers(t *testing.T, store *PeerStore, n int) {
	t.Helper()
	base := time.Now().UTC()
	for i := 0; i < n; i++ {
		key, _ := wgtypes.GenerateKey()
		psk, _ := wgtypes.GenerateKey()
		store.Set(PeerRecord{
			PeerID:       fmt.Sprintf("peer-%d", i),
			PublicKey:    key,
			PresharedKey: psk,
			AllowedIPs:   mustParseCIDRs(t, fmt.Sprintf("10.0.%d.%d/32", i/256, i%256+1)),
			CreatedAt:    base.Add(time.Duration(i) * time.Second),
		})
	}
}

// peerIDTest = "peer-1" is defined in wireguard_test.go (same package)

func TestStoredToRecordAllowedIPs(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	stored := peerRecordStored{
		PeerID:       peerIDTest,
		PublicKey:    key.String(),
		PresharedKey: psk.String(),
		AllowedIPs:   []string{"10.0.0.3/32", "fd00::3/128"},
		CreatedAt:    time.Now().UTC(),
	}
	rec, err := storedToRecord(stored)
	if err != nil {
		t.Fatalf("storedToRecord: %v", err)
	}
	if rec.PeerID != peerIDTest {
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
	psk, _ := wgtypes.GenerateKey()
	store := NewPeerStore()
	store.Set(PeerRecord{
		PeerID:       "roundtrip",
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   mustParseCIDRs(t, testAllowedIP, "fd00::1/128"),
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    nil,
	})

	dir := t.TempDir()
	path := filepath.Join(dir, testPeersFile)
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

func TestSaveToFileAndLoadFromFileRoundtripWithPresharedKey(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	store := NewPeerStore()
	store.Set(PeerRecord{
		PeerID:       "roundtrip-psk",
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   mustParseCIDRs(t, "10.0.0.2/32"),
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    nil,
	})

	dir := t.TempDir()
	path := filepath.Join(dir, testPeersFile)
	if err := store.SaveToFile(path); err != nil {
		t.Fatalf("SaveToFile: %v", err)
	}

	store2 := NewPeerStore()
	if err := store2.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	rec, ok := store2.Get("roundtrip-psk")
	if !ok {
		t.Fatalf("expected record after roundtrip")
	}
	if rec.PresharedKey != psk {
		t.Fatalf("preshared_key not preserved after roundtrip")
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
	path := filepath.Join(dir, testPeersFile)
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
	psk, _ := wgtypes.GenerateKey()
	stored := peerRecordStored{
		PeerID:       "  ",
		PublicKey:    key.String(),
		PresharedKey: psk.String(),
		AllowedIPs:   []string{testAllowedIP},
		CreatedAt:    time.Now().UTC(),
	}
	_, err := storedToRecord(stored)
	if err == nil {
		t.Fatal("storedToRecord(empty peer_id): expected error, got nil")
	}
}

func TestStoredToRecordEmptyAllowedIPs(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	stored := peerRecordStored{
		PeerID:       peerIDTest,
		PublicKey:    key.String(),
		PresharedKey: psk.String(),
		AllowedIPs:   []string{},
		CreatedAt:    time.Now().UTC(),
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

func TestStoredToRecordEmptyPresharedKey(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	stored := peerRecordStored{
		PeerID:       peerIDTest,
		PublicKey:    key.String(),
		PresharedKey: "",
		AllowedIPs:   []string{testAllowedIP},
		CreatedAt:    time.Now().UTC(),
	}
	_, err := storedToRecord(stored)
	if err == nil {
		t.Fatal("storedToRecord(empty preshared_key): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "preshared_key") {
		t.Errorf("expected error about preshared_key, got: %v", err)
	}
}

func TestStoredToRecordInvalidPublicKey(t *testing.T) {
	stored := peerRecordStored{
		PeerID:     peerIDTest,
		PublicKey:  "not-a-valid-key",
		AllowedIPs: []string{testAllowedIP},
	}
	_, err := storedToRecord(stored)
	if err == nil {
		t.Fatal("expected error for invalid public key")
	}
}

func TestStoredToRecordEmptyCIDRInAllowedIPs(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	stored := peerRecordStored{
		PeerID:       peerIDTest,
		PublicKey:    key.String(),
		PresharedKey: psk.String(),
		AllowedIPs:   []string{"", testAllowedIP}, // empty entry should be skipped
		CreatedAt:    time.Now().UTC(),
	}
	rec, err := storedToRecord(stored)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rec.AllowedIPs) != 1 {
		t.Fatalf("expected 1 net (empty skipped), got %d", len(rec.AllowedIPs))
	}
}

func TestStoredToRecordInvalidCIDRInAllowedIPs(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	stored := peerRecordStored{
		PeerID:       peerIDTest,
		PublicKey:    key.String(),
		PresharedKey: psk.String(),
		AllowedIPs:   []string{"not-a-cidr"},
		CreatedAt:    time.Now().UTC(),
	}
	_, err := storedToRecord(stored)
	if err == nil {
		t.Fatal("expected error for invalid CIDR in allowed_ips")
	}
}

func TestStoredToRecordAllCIDRsEmpty(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	stored := peerRecordStored{
		PeerID:       peerIDTest,
		PublicKey:    key.String(),
		PresharedKey: psk.String(),
		AllowedIPs:   []string{"", ""},
		CreatedAt:    time.Now().UTC(),
	}
	_, err := storedToRecord(stored)
	if err == nil {
		t.Fatal("expected error when all allowed_ips entries are empty strings")
	}
}

func TestLoadFromFileReadError(t *testing.T) {
	store := NewPeerStore()
	err := store.LoadFromFile("/nonexistent-dir/peers.json")
	if err == nil {
		t.Fatal("expected error for unreadable file")
	}
}

func TestLoadFromFileInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, testPeersFile)
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	store := NewPeerStore()
	if store.LoadFromFile(path) == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestPeerStoreConcurrentAccess(t *testing.T) {
	store := NewPeerStore()
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	rec := PeerRecord{
		PeerID:       peerIDTest,
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   mustParseCIDRs(t, testAllowedIP),
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); store.Set(rec) }()
		go func() { defer wg.Done(); store.Get(peerIDTest) }()
		go func() { defer wg.Done(); _ = store.List() }()
	}
	wg.Wait()
}

func TestSaveToFileUnwritablePath(t *testing.T) {
	store := NewPeerStore()
	err := store.SaveToFile("/nonexistent-dir-xyz/peers.json")
	if err == nil {
		t.Fatal("expected error when saving to unwritable path")
	}
}

func TestLoadFromFileIfExistsPermissionError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root, cannot test permission errors")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, testPeersFile)
	if err := os.WriteFile(path, []byte(`[]`), 0o000); err != nil {
		t.Fatalf("write: %v", err)
	}
	store := NewPeerStore()
	if store.LoadFromFileIfExists(path) == nil {
		t.Fatal("expected error for permission-denied file (non-ErrNotExist)")
	}
}

func TestLoadFromDataDuplicatePublicKey(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	keyStr := key.String()
	pskStr := psk.String()
	data := []byte(fmt.Sprintf(`[
		{"peer_id":"a","public_key":%q,"preshared_key":%q,"allowed_ips":[%q],"created_at":"2024-01-01T00:00:00Z"},
		{"peer_id":"b","public_key":%q,"preshared_key":%q,"allowed_ips":["10.0.0.2/32"],"created_at":"2024-01-01T00:00:00Z"}
	]`, keyStr, pskStr, testAllowedIP, keyStr, pskStr))
	store := NewPeerStore()
	err := store.loadFromData(data)
	if err == nil {
		t.Fatal("loadFromData(duplicate public_key): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate public_key") {
		t.Errorf("expected error about duplicate public_key, got: %v", err)
	}
}

// ---------- ListPaginated ----------

func TestListPaginatedOffsetBeyondTotal(t *testing.T) {
	store := NewPeerStore()
	makeStorePeers(t, store, 3)

	// offset == total
	records, total := store.ListPaginated(3, 10)
	if total != 3 {
		t.Fatalf("expected total 3, got %d", total)
	}
	if len(records) != 0 {
		t.Fatalf("expected empty slice for offset==total, got %d records", len(records))
	}

	// offset > total
	records, total = store.ListPaginated(5, 10)
	if total != 3 {
		t.Fatalf("expected total 3, got %d", total)
	}
	if len(records) != 0 {
		t.Fatalf("expected empty slice for offset>total, got %d records", len(records))
	}
}

func TestListPaginatedLimitZeroReturnsAll(t *testing.T) {
	store := NewPeerStore()
	makeStorePeers(t, store, 5)

	records, total := store.ListPaginated(0, 0)
	if total != 5 {
		t.Fatalf("expected total 5, got %d", total)
	}
	if len(records) != 5 {
		t.Fatalf("expected 5 records for limit=0, got %d", len(records))
	}
}
