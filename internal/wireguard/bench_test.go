package wireguard

import (
	"fmt"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// newBenchService returns a WireGuardService wired to a no-op fake client,
// suitable for benchmarks that do not exercise the kernel WireGuard path.
func newBenchService(b *testing.B, cidr string) *WireGuardService {
	b.Helper()
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		b.Fatalf("parse cidr: %v", err)
	}
	start, _, _ := ipv4Range(subnet)
	svc := &WireGuardService{
		client:    fakeWGClient{device: &wgtypes.Device{}},
		subnet4:   subnet,
		serverIP4: start,
		store:     NewPeerStore(),
	}
	svc.initUsedIPs()
	return svc
}

// ---------- IP allocation ----------

func BenchmarkAllocateOneIPv4(b *testing.B) {
	svc := newBenchService(b, "10.0.0.0/16")
	used := make(map[string]struct{})
	var hint uint32
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Refill used map so each iteration finds a free slot near the hint.
		if len(used) > 0 {
			used = make(map[string]struct{})
		}
		if _, err := allocateOneIPv4(svc.subnet4, used, &hint); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAllocateOneIPv4NearlyFull(b *testing.B) {
	// /24 with 253 addresses pre-filled — forces wrap-around scan.
	svc := newBenchService(b, "10.0.1.0/24")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		used := make(map[string]struct{})
		// Fill all but the last address.
		for j := 1; j <= 252; j++ {
			used[fmt.Sprintf("10.0.1.%d", j)] = struct{}{}
		}
		var hint uint32
		b.StartTimer()
		if _, err := allocateOneIPv4(svc.subnet4, used, &hint); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAllocateOneIPv6(b *testing.B) {
	_, subnet, _ := net.ParseCIDR("fd00::/120")
	used := make(map[string]struct{})
	var hint net.IP
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(used) > 0 {
			used = make(map[string]struct{})
		}
		if _, err := allocateOneIPv6(subnet, used, &hint); err != nil {
			b.Fatal(err)
		}
	}
}

// ---------- WireGuardService ----------

// BenchmarkEnsurePeerRotate measures the rotate path: the peer already exists
// and EnsurePeer is called again to refresh its keys/expiry.
func BenchmarkEnsurePeerRotate(b *testing.B) {
	svc := newBenchService(b, "10.0.0.0/16")
	if _, err := svc.EnsurePeer("bench-peer", nil, []string{"IPv4"}); err != nil {
		b.Fatalf("setup: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.EnsurePeer("bench-peer", nil, []string{"IPv4"}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEnsurePeerNew measures new peer creation. Uses a /8 subnet so that
// the IP pool is not exhausted even for large b.N values.
func BenchmarkEnsurePeerNew(b *testing.B) {
	svc := newBenchService(b, "10.0.0.0/8")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.EnsurePeer(fmt.Sprintf("peer-%d", i), nil, []string{"IPv4"}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDeletePeer measures peer deletion. The peer is re-inserted outside
// the timer between iterations so that each iteration deletes a fresh record.
func BenchmarkDeletePeer(b *testing.B) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	_, ipn, _ := net.ParseCIDR("10.0.0.2/32")
	rec := PeerRecord{
		PeerID:       "bench-peer",
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   []net.IPNet{*ipn},
		CreatedAt:    time.Now().UTC(),
	}
	svc := newBenchService(b, "10.0.0.0/16")
	svc.store.Set(rec)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := svc.DeletePeer("bench-peer"); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		svc.store.Set(rec)
		b.StartTimer()
	}
}

// ---------- PeerStore ----------

func BenchmarkPeerStoreSet(b *testing.B) {
	store := NewPeerStore()
	key, _ := wgtypes.GenerateKey()
	_, ipn, _ := net.ParseCIDR("10.0.0.2/32")
	rec := PeerRecord{
		PeerID:     "bench-peer",
		PublicKey:  key,
		AllowedIPs: []net.IPNet{*ipn},
		CreatedAt:  time.Now().UTC(),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Set(rec)
	}
}

func BenchmarkPeerStoreGet(b *testing.B) {
	store := NewPeerStore()
	key, _ := wgtypes.GenerateKey()
	_, ipn, _ := net.ParseCIDR("10.0.0.2/32")
	store.Set(PeerRecord{
		PeerID:     "bench-peer",
		PublicKey:  key,
		AllowedIPs: []net.IPNet{*ipn},
		CreatedAt:  time.Now().UTC(),
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Get("bench-peer")
	}
}

func BenchmarkPeerStoreGetParallel(b *testing.B) {
	store := NewPeerStore()
	key, _ := wgtypes.GenerateKey()
	_, ipn, _ := net.ParseCIDR("10.0.0.2/32")
	store.Set(PeerRecord{
		PeerID:     "bench-peer",
		PublicKey:  key,
		AllowedIPs: []net.IPNet{*ipn},
		CreatedAt:  time.Now().UTC(),
	})
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			store.Get("bench-peer")
		}
	})
}

func BenchmarkPeerStoreSetParallel(b *testing.B) {
	store := NewPeerStore()
	key, _ := wgtypes.GenerateKey()
	_, ipn, _ := net.ParseCIDR("10.0.0.2/32")
	rec := PeerRecord{
		PeerID:     "bench-peer",
		PublicKey:  key,
		AllowedIPs: []net.IPNet{*ipn},
		CreatedAt:  time.Now().UTC(),
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			store.Set(rec)
		}
	})
}

func BenchmarkPeerStoreListPaginated1000(b *testing.B) {
	store := NewPeerStore()
	for i := 0; i < 1000; i++ {
		key, _ := wgtypes.GenerateKey()
		_, ipn, _ := net.ParseCIDR(fmt.Sprintf("10.%d.%d.2/32", i/256, i%256))
		store.Set(PeerRecord{
			PeerID:     fmt.Sprintf("peer-%d", i),
			PublicKey:  key,
			AllowedIPs: []net.IPNet{*ipn},
			CreatedAt:  time.Now().UTC(),
		})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.ListPaginated(0, 50)
	}
}

func BenchmarkPeerStoreForEach1000(b *testing.B) {
	store := NewPeerStore()
	for i := 0; i < 1000; i++ {
		key, _ := wgtypes.GenerateKey()
		_, ipn, _ := net.ParseCIDR(fmt.Sprintf("10.%d.%d.2/32", i/256, i%256))
		store.Set(PeerRecord{
			PeerID:     fmt.Sprintf("peer-%d", i),
			PublicKey:  key,
			AllowedIPs: []net.IPNet{*ipn},
			CreatedAt:  time.Now().UTC(),
		})
	}
	n := 0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.ForEach(func(PeerRecord) { n++ })
	}
}
