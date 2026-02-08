package wireguard

import (
	"encoding/json"
	"net"
	"os"
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
	mu    sync.RWMutex
	peers map[string]PeerRecord
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
// Existing in-memory peers are replaced.
func (s *PeerStore) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var stored []peerRecordStored
	if err := json.Unmarshal(data, &stored); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers = make(map[string]PeerRecord, len(stored))
	for i := range stored {
		rec, err := storedToRecord(stored[i])
		if err != nil {
			return err
		}
		s.peers[rec.PeerID] = rec
	}
	return nil
}

// SaveToFile writes all peer records to a JSON file (allowed_ips).
func (s *PeerStore) SaveToFile(path string) error {
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
	return os.WriteFile(path, data, 0o600)
}
