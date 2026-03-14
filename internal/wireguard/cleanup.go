package wireguard

import (
	"context"
	"log"
	"runtime/debug"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// RunExpiredPeersCleanup runs a loop that periodically removes peers whose ExpiresAt is in the past.
// It exits when ctx is canceled. First run is immediate; then every interval.
func (s *WireGuardService) RunExpiredPeersCleanup(ctx context.Context, interval time.Duration) {
	s.runCleanupSafe()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runCleanupSafe()
		}
	}
}

// runCleanupSafe runs cleanupExpiredPeers and recovers any panic so the cleanup goroutine keeps running.
func (s *WireGuardService) runCleanupSafe() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("cleanup panic (recovered): %v\n%s", r, debug.Stack())
		}
	}()
	s.cleanupExpiredPeers()
}

func (s *WireGuardService) cleanupExpiredPeers() {
	now := time.Now().UTC()

	// Collect candidates without holding any lock.
	var candidates []string
	s.store.ForEach(func(rec PeerRecord) {
		if rec.ExpiresAt != nil && !now.Before(*rec.ExpiresAt) {
			candidates = append(candidates, rec.PeerID)
		}
	})

	for _, peerID := range candidates {
		deleted, err := s.deleteExpiredPeerLocked(peerID, now)
		if err != nil {
			log.Printf("cleanup expired peer %s: %v", peerID, err)
			continue
		}
		if !deleted {
			continue // extended or removed by a concurrent operation
		}
		if err := s.savePersist(); err != nil {
			log.Printf("cleanup: save peer store: %v", err)
		}
		log.Printf("expired peer removed: peerId=%s", peerID)
	}
}

// deleteExpiredPeerLocked removes peerID from the device and store only if it
// is still expired at the time s.mu is acquired. This prevents a race with a
// concurrent EnsurePeer that extends the peer's expiry between our initial
// ForEach snapshot and the actual deletion.
func (s *WireGuardService) deleteExpiredPeerLocked(peerID string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.store.Get(peerID)
	if !ok {
		return false, nil // already removed by a concurrent operation
	}
	if record.ExpiresAt == nil || now.Before(*record.ExpiresAt) {
		return false, nil // made permanent or extended by a concurrent EnsurePeer
	}

	remove := wgtypes.PeerConfig{PublicKey: record.PublicKey, Remove: true}
	if err := s.configureDevice(wgtypes.Config{Peers: []wgtypes.PeerConfig{remove}}); err != nil {
		return false, err
	}
	s.store.Delete(peerID)
	return true, nil
}
