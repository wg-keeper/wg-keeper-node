package wireguard

import (
	"context"
	"log"
	"time"
)

// RunExpiredPeersCleanup runs a loop that periodically removes peers whose ExpiresAt is in the past.
// It exits when ctx is cancelled.
func (s *WireGuardService) RunExpiredPeersCleanup(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanupExpiredPeers()
		}
	}
}

func (s *WireGuardService) cleanupExpiredPeers() {
	now := time.Now().UTC()
	for _, rec := range s.store.List() {
		// Re-read from store so we don't delete a peer that was extended (e.g. by a concurrent POST) after List().
		actual, ok := s.store.Get(rec.PeerID)
		if !ok {
			continue // already removed
		}
		if actual.ExpiresAt == nil {
			continue // permanent
		}
		if now.Before(*actual.ExpiresAt) {
			continue // extended or not yet expired
		}
		if err := s.DeletePeer(rec.PeerID); err != nil {
			log.Printf("cleanup expired peer %s: %v", rec.PeerID, err)
			continue
		}
		log.Printf("expired peer removed: peerId=%s", rec.PeerID)
	}
}
