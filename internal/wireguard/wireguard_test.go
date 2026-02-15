package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	msgUnexpectedError = "unexpected error: %v"
	ipServerTest       = "10.0.0.1"
	ipPeerTest         = "10.0.0.2"
	peerIDTest         = "peer-1"
	subnetTestCIDR     = "10.0.0.0/24"
)

type fakeWGClient struct {
	device       *wgtypes.Device
	err          error
	configureErr error
}

func (f fakeWGClient) Device(_ string) (*wgtypes.Device, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.device, nil
}

func (f fakeWGClient) ConfigureDevice(_ string, _ wgtypes.Config) error {
	return f.configureErr
}

func ipNet(t *testing.T, ip string) net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(fmt.Sprintf("%s/32", ip))
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	return *n
}

func TestValidateAddressFamiliesEmptyReturnsNodeFamilies(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{subnet4: subnet4, serverIP4: net.ParseIP(ipServerTest), store: NewPeerStore()}
	families, err := svc.ValidateAddressFamilies(nil)
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if len(families) != 1 || families[0] != FamilyIPv4 {
		t.Fatalf("expected [IPv4], got %v", families)
	}
}

func TestValidateAddressFamiliesUnsupported(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{subnet4: subnet4, serverIP4: net.ParseIP(ipServerTest), store: NewPeerStore()}
	_, err := svc.ValidateAddressFamilies([]string{FamilyIPv6})
	if !errors.Is(err, ErrUnsupportedAddressFamily) {
		t.Fatalf("expected ErrUnsupportedAddressFamily, got %v", err)
	}
}

func TestResolveServerIP4(t *testing.T) {
	_, subnet, _ := net.ParseCIDR(subnetTestCIDR)

	ip, err := resolveServerIP4(subnet, "10.0.0.10")
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if ip.String() != "10.0.0.10" {
		t.Fatalf("unexpected ip: %s", ip.String())
	}

	if _, err := resolveServerIP4(subnet, "10.0.1.10"); err == nil {
		t.Fatalf("expected error for IP outside subnet")
	}
}

func TestAllocateIPSkipsUsed(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.0.0.0/29")
	serverIP := net.ParseIP(ipServerTest)

	device := &wgtypes.Device{
		Peers: []wgtypes.Peer{
			{AllowedIPs: []net.IPNet{ipNet(t, "10.0.0.3")}},
		},
	}

	svc := &WireGuardService{
		client:     fakeWGClient{device: device},
		deviceName: "wg0",
		subnet4:    subnet,
		serverIP4:  serverIP,
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:     peerIDTest,
		PublicKey:  wgtypes.Key{},
		AllowedIPs: []net.IPNet{ipNet(t, ipPeerTest)},
	})

	ips, err := svc.allocateIPs([]string{FamilyIPv4})
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if len(ips) != 1 || ips[0].IP.String() != "10.0.0.4" {
		t.Fatalf("expected [10.0.0.4/32], got %v", ips)
	}
}

func TestAllocateIPNoAvailable(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.0.0.0/30")
	serverIP := net.ParseIP(ipServerTest)

	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet,
		serverIP4:  serverIP,
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:     peerIDTest,
		PublicKey:  wgtypes.Key{},
		AllowedIPs: []net.IPNet{ipNet(t, ipPeerTest)},
	})

	_, err := svc.allocateIPs([]string{FamilyIPv4})
	if !errors.Is(err, ErrNoAvailableIP) {
		t.Fatalf("expected ErrNoAvailableIP, got %v", err)
	}
}

func TestStatsActivePeers(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.0.0.0/29")
	serverIP := net.ParseIP(ipServerTest)
	now := time.Now()

	device := &wgtypes.Device{
		Peers: []wgtypes.Peer{
			{LastHandshakeTime: now.Add(-1 * time.Minute)},
			{LastHandshakeTime: now.Add(-10 * time.Minute)},
		},
	}

	svc := &WireGuardService{
		client:     fakeWGClient{device: device},
		deviceName: "wg0",
		subnet4:    subnet,
		serverIP4:  serverIP,
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:     peerIDTest,
		PublicKey:  wgtypes.Key{},
		AllowedIPs: []net.IPNet{ipNet(t, ipPeerTest)},
	})

	stats, err := svc.Stats()
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if stats.Peers.Active != 1 {
		t.Fatalf("expected 1 active peer, got %d", stats.Peers.Active)
	}
	if stats.Peers.Issued != 1 {
		t.Fatalf("expected 1 issued peer, got %d", stats.Peers.Issued)
	}
}

func TestRunExpiredPeersCleanup_ExitsOnContextCancel(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		svc.RunExpiredPeersCleanup(ctx, time.Minute)
		close(done)
	}()
	cancel()
	select {
	case <-done:
		// expected
	case <-time.After(2 * time.Second):
		t.Fatal("RunExpiredPeersCleanup did not exit after context cancel")
	}
}

func TestRunExpiredPeersCleanup_RemovesExpiredPeer(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	expiredAt := time.Now().UTC().Add(-time.Hour)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	key, _ := wgtypes.GenerateKey()
	svc.store.Set(PeerRecord{
		PeerID:     "expired-peer",
		PublicKey:  key,
		AllowedIPs: []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  &expiredAt,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go svc.RunExpiredPeersCleanup(ctx, 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond)

	list, err := svc.ListPeers()
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 peers after cleanup, got %d", len(list))
	}
}

func TestRunExpiredPeersCleanup_KeepsPermanentPeer(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	key, _ := wgtypes.GenerateKey()
	svc.store.Set(PeerRecord{
		PeerID:     "permanent-peer",
		PublicKey:  key,
		AllowedIPs: []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  nil, // permanent
	})

	svc.runCleanupSafe()
	time.Sleep(10 * time.Millisecond)

	list, err := svc.ListPeers()
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(list) != 1 || list[0].PeerID != "permanent-peer" {
		t.Errorf("expected 1 permanent peer to remain, got %v", list)
	}
}

func TestCleanupExpiredPeersDeletePeerError(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	expiredAt := time.Now().UTC().Add(-time.Hour)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}, configureErr: errors.New("device busy")},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:     "expired-fail",
		PublicKey:  key,
		AllowedIPs: []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  &expiredAt,
	})
	svc.runCleanupSafe()
	list, err := svc.ListPeers()
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("peer should remain when DeletePeer fails, got %d peers", len(list))
	}
}

func TestGetPeerSuccess(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	device := &wgtypes.Device{
		Peers: []wgtypes.Peer{
			{PublicKey: key, ReceiveBytes: 100, TransmitBytes: 200},
		},
	}
	svc := &WireGuardService{
		client:     fakeWGClient{device: device},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:     peerIDTest,
		PublicKey:  key,
		AllowedIPs: []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:  time.Now().UTC(),
	})

	detail, err := svc.GetPeer(peerIDTest)
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if detail.PeerID != peerIDTest || detail.ReceiveBytes != 100 || detail.TransmitBytes != 200 {
		t.Errorf("unexpected detail: %+v", detail)
	}
}

func TestGetPeerNotFound(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	_, err := svc.GetPeer("nonexistent")
	if !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("expected ErrPeerNotFound, got %v", err)
	}
}

func TestGetPeerDeviceError(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{err: errors.New("device error")},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{PeerID: peerIDTest, PublicKey: key, AllowedIPs: []net.IPNet{ipNet(t, ipPeerTest)}})
	_, err := svc.GetPeer(peerIDTest)
	if err == nil {
		t.Fatal("expected error when device fails")
	}
}

func TestServerInfo(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	device := &wgtypes.Device{PublicKey: key, ListenPort: 51820}
	svc := &WireGuardService{
		client:     fakeWGClient{device: device},
		deviceName: "wg0",
		store:      NewPeerStore(),
	}
	pub, port, err := svc.ServerInfo()
	if err != nil {
		t.Fatalf("ServerInfo: %v", err)
	}
	if pub != key.String() || port != 51820 {
		t.Errorf("got publicKey=%s port=%d", pub, port)
	}
}

func TestRecordAllowedIPsInSubnets(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR("10.0.0.0/24")
	_, subnet6, _ := net.ParseCIDR("fd00::/64")
	svc := &WireGuardService{
		subnet4:   subnet4,
		serverIP4: net.ParseIP("10.0.0.1"),
		subnet6:   subnet6,
		serverIP6: net.ParseIP("fd00::1"),
		store:     NewPeerStore(),
	}

	recIn := PeerRecord{AllowedIPs: []net.IPNet{ipNet(t, "10.0.0.2"), ipNet6(t, "fd00::2")}}
	if !svc.recordAllowedIPsInSubnets(recIn) {
		t.Error("expected true for IPs in both subnets")
	}

	recOut := PeerRecord{AllowedIPs: []net.IPNet{ipNet(t, "192.168.1.1")}}
	if svc.recordAllowedIPsInSubnets(recOut) {
		t.Error("expected false for IP outside subnets")
	}

	svc4Only := &WireGuardService{subnet4: subnet4, serverIP4: net.ParseIP("10.0.0.1"), store: NewPeerStore()}
	rec4 := PeerRecord{AllowedIPs: []net.IPNet{ipNet(t, "10.0.0.3")}}
	if !svc4Only.recordAllowedIPsInSubnets(rec4) {
		t.Error("expected true for IPv4 in subnet")
	}
}

func ipNet6(t *testing.T, ip string) net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(ip + "/128")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	return *n
}

func TestSavePersist(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/peers.json"
	svc := &WireGuardService{store: NewPeerStore(), persistPath: path}
	if err := svc.savePersist(); err != nil {
		t.Fatalf("savePersist: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file should exist: %v", err)
	}
}

func TestSavePersistNoPath(t *testing.T) {
	svc := &WireGuardService{store: NewPeerStore(), persistPath: ""}
	if err := svc.savePersist(); err != nil {
		t.Fatalf("savePersist with empty path: %v", err)
	}
}

func TestEnsurePeerNewPeer(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR("10.0.0.0/29")
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	info, err := svc.EnsurePeer("new-peer", nil, nil)
	if err != nil {
		t.Fatalf("EnsurePeer: %v", err)
	}
	if info.PeerID != "new-peer" || info.PublicKey == "" || info.PrivateKey == "" {
		t.Errorf("unexpected PeerInfo: %+v", info)
	}
	if len(info.AllowedIPs) != 1 || !strings.Contains(info.AllowedIPs[0], "10.0.0.") {
		t.Errorf("unexpected AllowedIPs: %v", info.AllowedIPs)
	}
	_, ok := svc.store.Get("new-peer")
	if !ok {
		t.Error("peer should be in store")
	}
}

func TestEnsurePeerDuplicateRotates(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR("10.0.0.0/29")
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{Peers: []wgtypes.Peer{{PublicKey: key, AllowedIPs: []net.IPNet{ipNet(t, ipPeerTest)}}}}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:     peerIDTest,
		PublicKey:  key,
		AllowedIPs: []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:  time.Now().UTC(),
	})
	info, err := svc.EnsurePeer(peerIDTest, nil, nil)
	if err != nil {
		t.Fatalf("EnsurePeer rotate: %v", err)
	}
	if info.PeerID != peerIDTest {
		t.Errorf("PeerID: got %s", info.PeerID)
	}
	rec, ok := svc.store.Get(peerIDTest)
	if !ok {
		t.Fatal("peer should still be in store")
	}
	if rec.PublicKey == key {
		t.Error("public key should have been rotated")
	}
}
