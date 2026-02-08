package wireguard

import (
	"net"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type PeerRecord struct {
	PeerID    string
	PublicKey wgtypes.Key
	AllowedIP net.IPNet
	CreatedAt time.Time
	ExpiresAt *time.Time // nil = permanent peer
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
