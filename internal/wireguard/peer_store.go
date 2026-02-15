package wireguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type PeerRecord struct {
	PeerID     string
	PublicKey  wgtypes.Key
	AllowedIPs []net.IPNet // one per address family (IPv4 and/or IPv6)
	CreatedAt  time.Time
	ExpiresAt  *time.Time // nil = permanent peer
}

// peerRecordStored is the JSON format for persistence (IPv4 and/or IPv6 in allowed_ips).
type peerRecordStored struct {
	PeerID     string     `json:"peer_id"`
	PublicKey  string     `json:"public_key"` // base64
	AllowedIPs []string   `json:"allowed_ips"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

func storedToRecord(s peerRecordStored) (PeerRecord, error) {
	if strings.TrimSpace(s.PeerID) == "" {
		return PeerRecord{}, errors.New("peer_id is required and must be non-empty")
	}
	key, err := wgtypes.ParseKey(s.PublicKey)
	if err != nil {
		return PeerRecord{}, err
	}
	nets := make([]net.IPNet, 0, len(s.AllowedIPs))
	for _, cidr := range s.AllowedIPs {
		if cidr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return PeerRecord{}, err
		}
		nets = append(nets, *ipNet)
	}
	if len(nets) == 0 {
		return PeerRecord{}, errors.New("allowed_ips is required and must contain at least one valid CIDR")
	}
	return PeerRecord{
		PeerID:     s.PeerID,
		PublicKey:  key,
		AllowedIPs: nets,
		CreatedAt:  s.CreatedAt,
		ExpiresAt:  s.ExpiresAt,
	}, nil
}

func recordToStored(r PeerRecord) peerRecordStored {
	allowedIPs := make([]string, len(r.AllowedIPs))
	for i := range r.AllowedIPs {
		allowedIPs[i] = r.AllowedIPs[i].String()
	}
	return peerRecordStored{
		PeerID:     r.PeerID,
		PublicKey:  r.PublicKey.String(),
		AllowedIPs: allowedIPs,
		CreatedAt:  r.CreatedAt,
		ExpiresAt:  r.ExpiresAt,
	}
}

type PeerStore struct {
	mu     sync.RWMutex
	saveMu sync.Mutex // serializes SaveToFile calls
	peers  map[string]PeerRecord
}

func NewPeerStore() *PeerStore {
	return &PeerStore{
		peers: make(map[string]PeerRecord),
	}
}

func (s *PeerStore) Get(peerID string) (PeerRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.peers[peerID]
	return record, ok
}

func (s *PeerStore) Set(record PeerRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers[record.PeerID] = record
}

func (s *PeerStore) Delete(peerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.peers, peerID)
}

func (s *PeerStore) List() []PeerRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PeerRecord, 0, len(s.peers))
	for _, record := range s.peers {
		out = append(out, record)
	}
	return out
}

// LoadFromFile loads peer records from a JSON file (format: allowed_ips for IPv4/IPv6).
// Existing in-memory peers are replaced. Returns error if file is missing, empty, or invalid.
func (s *PeerStore) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return s.loadFromData(data)
}

// LoadFromFileIfExists loads peer records from a JSON file when persistence is enabled.
// If the file does not exist (os.ErrNotExist), returns nil and leaves the store empty.
// If the file exists but is empty, invalid JSON, has duplicate peer_id, or any invalid record, returns an error.
func (s *PeerStore) LoadFromFileIfExists(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return s.loadFromData(data)
}

// loadFromData replaces store contents with parsed data. Caller ensures data is read from file.
// Empty data, invalid JSON, non-array root, duplicate peer_id, or invalid record cause an error.
func (s *PeerStore) loadFromData(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("peer store file is empty")
	}
	var stored []peerRecordStored
	if err := json.Unmarshal(data, &stored); err != nil {
		return fmt.Errorf("peer store file: invalid JSON: %w", err)
	}
	if stored == nil {
		return fmt.Errorf("peer store file: root must be a JSON array, not null")
	}
	seenPeerID := make(map[string]bool, len(stored))
	seenPublicKey := make(map[wgtypes.Key]bool, len(stored))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers = make(map[string]PeerRecord, len(stored))
	for i := range stored {
		rec, err := storedToRecord(stored[i])
		if err != nil {
			return fmt.Errorf("peer store file: record %d (peer_id %q): %w", i, stored[i].PeerID, err)
		}
		if seenPeerID[rec.PeerID] {
			return fmt.Errorf("peer store file: duplicate peer_id %q", rec.PeerID)
		}
		if seenPublicKey[rec.PublicKey] {
			return fmt.Errorf("peer store file: duplicate public_key in record %d (peer_id %q)", i, rec.PeerID)
		}
		seenPeerID[rec.PeerID] = true
		seenPublicKey[rec.PublicKey] = true
		s.peers[rec.PeerID] = rec
	}
	return nil
}

// SaveToFile writes all peer records to a JSON file (allowed_ips).
// Writes atomically via a temp file and rename. Serialized with saveMu.
func (s *PeerStore) SaveToFile(path string) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.RLock()
	list := make([]PeerRecord, 0, len(s.peers))
	for _, r := range s.peers {
		list = append(list, r)
	}
	s.mu.RUnlock()

	stored := make([]peerRecordStored, len(list))
	for i := range list {
		stored[i] = recordToStored(list[i])
	}
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}
