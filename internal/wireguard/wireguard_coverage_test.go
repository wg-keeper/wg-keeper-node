package wireguard

import (
	"errors"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	testSubnet4        = "10.0.0.0/24"
	testServerIP4      = "10.0.0.1"
	testSubnet6        = "fd00::/112"
	testSubnet6Large   = "fd00::/64"
	testSubnet6Small   = "fd00::/120"
	testServerIP6      = "fd00::1"
	testServerIP6InBig = "fd00::5"
	testServerIP6Out   = "fd01::1"

	testPeerIP4              = "10.0.0.2/32"
	testOutsidePeerID        = "outside-peer"
	testErrUnexpectedFormat  = "unexpected error: %v"
	testErrDeviceBusyMessage = "device busy"
	testErrDeviceError       = "device error"
	testErrDeviceOffline     = "device offline"
	testExpiryPeerID         = "expiry-peer"
	testDelFailPeerID        = "del-fail"
	msgExpectedTwoFamilies   = "expected 2 families, got %v"
)

// ---------- setupSubnet4 / setupSubnet6 ----------

// ---------- DeletePeer not found ----------

func TestDeletePeerNotFound(t *testing.T) {
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		store:      NewPeerStore(),
	}
	err := svc.DeletePeer("nonexistent")
	if !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("expected ErrPeerNotFound, got %v", err)
	}
}

// ---------- EnsurePeer with invalid address family ----------

func TestEnsurePeerInvalidAddressFamily(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(testServerIP4),
		store:      NewPeerStore(),
	}
	_, err := svc.EnsurePeer("peer-bad-family", nil, []string{"InvalidFamily"})
	if err == nil {
		t.Fatal("expected error for invalid address family")
	}
}

// ---------- rotatePeer with IPv6 AllowedIPs ----------

func TestRotatePeerIPv6Family(t *testing.T) {
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet6:    subnet6,
		serverIP6:  net.ParseIP(testServerIP6),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       "ipv6-peer",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, "fd00::2/128"),
	})
	info, err := svc.EnsurePeer("ipv6-peer", nil, nil)
	if err != nil {
		t.Fatalf("EnsurePeer IPv6 rotate: %v", err)
	}
	if len(info.AddressFamilies) != 1 || info.AddressFamilies[0] != FamilyIPv6 {
		t.Errorf("expected [IPv6] families, got %v", info.AddressFamilies)
	}
}

// ---------- ipv4Range with IPv6 subnet ----------

func TestIpv4RangeIPv6Subnet(t *testing.T) {
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	_, _, err := ipv4Range(subnet6)
	if err == nil {
		t.Fatal("expected error when IPv6 subnet passed to ipv4Range")
	}
}

// ---------- allocateOneIPv4 error via broken subnet ----------

func TestAllocateIPsIPv4RangeError(t *testing.T) {
	// /31 causes ipv4Range to fail inside allocateOneIPv4
	_, subnet31, _ := net.ParseCIDR("10.0.0.0/31")
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet31,
		serverIP4:  net.ParseIP(testServerIP4),
		store:      NewPeerStore(),
	}
	_, err := svc.allocateIPs([]string{FamilyIPv4})
	if err == nil {
		t.Fatal("expected error from allocateOneIPv4 for /31 subnet")
	}
}

// ---------- allocateOneIPv6 with large subnet (ones < 112) ----------

func TestAllocateOneIPv6LargeSubnet(t *testing.T) {
	_, subnet, _ := net.ParseCIDR(testSubnet6Large) // /64, ones=64 < 112
	used := map[string]struct{}{}
	ipNet, err := allocateOneIPv6(subnet, used)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ipNet.IP.To4() != nil {
		t.Error("expected IPv6 address")
	}
}

// ---------- possiblePeerCountIPv6 error ----------

func TestPossiblePeerCountIPv6TooSmall(t *testing.T) {
	_, subnet128, _ := net.ParseCIDR("fd00::1/128")
	_, err := possiblePeerCountIPv6(subnet128, nil)
	if err == nil {
		t.Fatal("expected error for /128 IPv6 subnet")
	}
}

// ---------- possiblePeerCountTotal IPv6 error ----------

func TestPossiblePeerCountTotalSubnet6Error(t *testing.T) {
	_, subnet128, _ := net.ParseCIDR("fd00::1/128")
	svc := &WireGuardService{subnet6: subnet128, store: NewPeerStore()}
	_, err := svc.possiblePeerCountTotal()
	if err == nil {
		t.Fatal("expected error for /128 subnet6 in possiblePeerCountTotal")
	}
}

// ---------- resolveServerIP4 empty serverIP with bad subnet ----------

func TestResolveServerIP4EmptyServerIPBadSubnet(t *testing.T) {
	_, subnet31, _ := net.ParseCIDR("10.0.0.0/31")
	_, err := resolveServerIP4(subnet31, "")
	if err == nil {
		t.Fatal("expected error when serverIP is empty and subnet is /31 (too small)")
	}
}

func TestSetupSubnet6InvalidCIDR(t *testing.T) {
	if _, _, err := setupSubnet6("not-a-cidr", ""); err == nil {
		t.Fatal("expected error for invalid CIDR in setupSubnet6")
	}
}

func TestPossiblePeerCountTotalSubnet4Error(t *testing.T) {
	// /31 subnet causes ipv4Range to fail ("too small")
	_, subnet31, _ := net.ParseCIDR("10.0.0.0/31")
	svc := &WireGuardService{subnet4: subnet31, store: NewPeerStore()}
	_, err := svc.possiblePeerCountTotal()
	if err == nil {
		t.Fatal("expected error for /31 subnet in possiblePeerCountTotal")
	}
}

func TestEnsurePeerConfigureDeviceError(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}, configureErr: errors.New(testErrDeviceBusyMessage)},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(testServerIP4),
		store:      NewPeerStore(),
	}
	_, err := svc.EnsurePeer("brand-new-peer", nil, nil)
	if err == nil {
		t.Fatal("expected error when ConfigureDevice fails for new peer")
	}
}

func TestSetupSubnet4EmptyReturnsNil(t *testing.T) {
	sub, ip, err := setupSubnet4("", "")
	if err != nil || sub != nil || ip != nil {
		t.Fatalf("expected nil results for empty subnet, got sub=%v ip=%v err=%v", sub, ip, err)
	}
}

func TestSetupSubnet4ValidNoServerIP(t *testing.T) {
	sub, ip, err := setupSubnet4(testSubnet4, "")
	if err != nil {
		t.Fatalf(testErrUnexpectedFormat, err)
	}
	if sub == nil || ip == nil {
		t.Fatal("expected non-nil subnet and server IP")
	}
	if ip.String() != testServerIP4 {
		t.Errorf("expected default server IP %s, got %s", testServerIP4, ip.String())
	}
}

func TestSetupSubnet4InvalidCIDR(t *testing.T) {
	if _, _, err := setupSubnet4("not-a-cidr", ""); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestSetupSubnet4IPv6Rejected(t *testing.T) {
	if _, _, err := setupSubnet4(testSubnet6Large, ""); err == nil {
		t.Fatal("expected error for IPv6 passed as subnet4")
	}
}

func TestSetupSubnet4ServerIPOutsideSubnet(t *testing.T) {
	if _, _, err := setupSubnet4(testSubnet4, "192.168.1.1"); err == nil {
		t.Fatal("expected error for server IP outside subnet")
	}
}

func TestSetupSubnet6EmptyReturnsNil(t *testing.T) {
	sub, ip, err := setupSubnet6("", "")
	if err != nil || sub != nil || ip != nil {
		t.Fatalf("expected nil results, got sub=%v ip=%v err=%v", sub, ip, err)
	}
}

func TestSetupSubnet6ValidNoServerIP(t *testing.T) {
	sub, ip, err := setupSubnet6(testSubnet6, "")
	if err != nil {
		t.Fatalf(testErrUnexpectedFormat, err)
	}
	if sub == nil || ip == nil {
		t.Fatal("expected non-nil subnet and server IP")
	}
}

func TestSetupSubnet6IPv4Rejected(t *testing.T) {
	if _, _, err := setupSubnet6(testSubnet4, ""); err == nil {
		t.Fatal("expected error for IPv4 passed as subnet6")
	}
}

// ---------- reconcileStoreWithSubnets ----------

func TestReconcileStoreWithSubnetsPeerInsideKept(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(testServerIP4),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       "inside-peer",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
	})

	changed := svc.reconcileStoreWithSubnets()
	if changed {
		t.Error("expected no change: peer is inside subnet")
	}
	if _, ok := svc.store.Get("inside-peer"); !ok {
		t.Error("peer should remain in store")
	}
}

func TestReconcileStoreWithSubnetsOutsidePeerRemoved(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(testServerIP4),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       testOutsidePeerID,
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, "192.168.1.5/32"),
	})

	changed := svc.reconcileStoreWithSubnets()
	if !changed {
		t.Error("expected changed=true: peer is outside subnet")
	}
	if _, ok := svc.store.Get(testOutsidePeerID); ok {
		t.Error("peer should have been removed from store")
	}
}

func TestReconcileStoreWithSubnetsDeviceErrorLogged(t *testing.T) {
	// ConfigureDevice fails: peer should still be removed from store.
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}, configureErr: errors.New("device busy")},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(testServerIP4),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       testOutsidePeerID,
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, "192.168.1.5/32"),
	})

	changed := svc.reconcileStoreWithSubnets()
	if !changed {
		t.Error("expected changed=true")
	}
	if _, ok := svc.store.Get(testOutsidePeerID); ok {
		t.Error("peer should be removed from store even when device fails")
	}
}

// ---------- reconcileStoreWithDevice ----------

func TestReconcileStoreWithDeviceMissingPeerAdded(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	// Device has no peers; store has one. reconcile should add it.
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       "missing-peer",
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
	})

	if err := svc.reconcileStoreWithDevice(); err != nil {
		t.Fatalf("reconcileStoreWithDevice: %v", err)
	}
}

func TestReconcileStoreWithDevicePresentPeerSkipped(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	// Device already has the peer; nothing to add.
	device := &wgtypes.Device{
		Peers: []wgtypes.Peer{{PublicKey: key}},
	}
	svc := &WireGuardService{
		client:     fakeWGClient{device: device},
		deviceName: "wg0",
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       "present-peer",
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
	})

	if err := svc.reconcileStoreWithDevice(); err != nil {
		t.Fatalf("reconcileStoreWithDevice: %v", err)
	}
}

func TestReconcileStoreWithDeviceDeviceError(t *testing.T) {
	svc := &WireGuardService{
		client:     fakeWGClient{err: errors.New("device offline")},
		deviceName: "wg0",
		store:      NewPeerStore(),
	}
	if err := svc.reconcileStoreWithDevice(); err == nil {
		t.Fatal("expected error when device is unavailable")
	}
}

// ---------- possiblePeerCountIPv6 ----------

func TestPossiblePeerCountIPv6LargeSubnet(t *testing.T) {
	// /64 has way more than 65536 addresses → capped at maxIPv6PeersReported
	_, subnet, _ := net.ParseCIDR(testSubnet6Large)
	n, err := possiblePeerCountIPv6(subnet, nil)
	if err != nil {
		t.Fatalf(testErrUnexpectedFormat, err)
	}
	if n != maxIPv6PeersReported {
		t.Errorf("expected cap of %d, got %d", maxIPv6PeersReported, n)
	}
}

func TestPossiblePeerCountIPv6LargeSubnetServerIPInRange(t *testing.T) {
	// server IP is inside the large subnet → count decremented by 1
	_, subnet, _ := net.ParseCIDR(testSubnet6Large)
	serverIP := net.ParseIP(testServerIP6InBig)
	n, err := possiblePeerCountIPv6(subnet, serverIP)
	if err != nil {
		t.Fatalf(testErrUnexpectedFormat, err)
	}
	if n != maxIPv6PeersReported-1 {
		t.Errorf("expected %d (server IP deducted), got %d", maxIPv6PeersReported-1, n)
	}
}

func TestPossiblePeerCountIPv6LargeSubnetServerIPOutsideRange(t *testing.T) {
	// server IP is outside the subnet → count stays at cap
	_, subnet, _ := net.ParseCIDR(testSubnet6Large)
	serverIP := net.ParseIP(testServerIP6Out) // different prefix
	n, err := possiblePeerCountIPv6(subnet, serverIP)
	if err != nil {
		t.Fatalf(testErrUnexpectedFormat, err)
	}
	if n != maxIPv6PeersReported {
		t.Errorf("expected cap of %d, got %d", maxIPv6PeersReported, n)
	}
}

func TestPossiblePeerCountIPv6SmallSubnetWithServerIP(t *testing.T) {
	// /120 (ones=120 ≥ 112) → iterates; server IP is excluded
	_, subnet, _ := net.ParseCIDR(testSubnet6Small)
	serverIP := net.ParseIP(testServerIP6)
	n, err := possiblePeerCountIPv6(subnet, serverIP)
	if err != nil {
		t.Fatalf(testErrUnexpectedFormat, err)
	}
	// /120 = 256 addresses, 2 reserved (start/end), server excluded → 253
	withoutServer, _ := possiblePeerCountIPv6(subnet, nil)
	if n != withoutServer-1 {
		t.Errorf("expected server IP to reduce count by 1: without=%d with=%d", withoutServer, n)
	}
}

// ---------- possiblePeerCountTotal ----------

func TestPossiblePeerCountTotalDualStack(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{
		subnet4:   subnet4,
		serverIP4: net.ParseIP(testServerIP4),
		subnet6:   subnet6,
		serverIP6: net.ParseIP(testServerIP6),
		store:     NewPeerStore(),
	}
	n, err := svc.possiblePeerCountTotal()
	if err != nil {
		t.Fatalf(testErrUnexpectedFormat, err)
	}
	v4, _ := possiblePeerCount(subnet4, net.ParseIP(testServerIP4))
	v6, _ := possiblePeerCountIPv6(subnet6, net.ParseIP(testServerIP6))
	if n != v4+v6 {
		t.Errorf("expected %d+%d=%d, got %d", v4, v6, v4+v6, n)
	}
}

func TestPossiblePeerCountTotalIPv6Only(t *testing.T) {
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{
		subnet6:   subnet6,
		serverIP6: net.ParseIP(testServerIP6),
		store:     NewPeerStore(),
	}
	n, err := svc.possiblePeerCountTotal()
	if err != nil {
		t.Fatalf(testErrUnexpectedFormat, err)
	}
	if n <= 0 {
		t.Errorf("expected positive count, got %d", n)
	}
}

// ---------- allocateIPs ----------

func TestAllocateIPsIPv6Only(t *testing.T) {
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet6:    subnet6,
		serverIP6:  net.ParseIP(testServerIP6),
		store:      NewPeerStore(),
	}
	ips, err := svc.allocateIPs([]string{FamilyIPv6})
	if err != nil {
		t.Fatalf(testErrUnexpectedFormat, err)
	}
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips))
	}
	if ips[0].IP.To4() != nil {
		t.Error("expected IPv6 address, got IPv4")
	}
}

func TestAllocateIPsDualStack(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(testServerIP4),
		subnet6:    subnet6,
		serverIP6:  net.ParseIP(testServerIP6),
		store:      NewPeerStore(),
	}
	ips, err := svc.allocateIPs([]string{FamilyIPv4, FamilyIPv6})
	if err != nil {
		t.Fatalf(testErrUnexpectedFormat, err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs (one per family), got %d", len(ips))
	}
}

func TestAllocateIPsDeviceError(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	svc := &WireGuardService{
		client:     fakeWGClient{err: errors.New(testErrDeviceError)},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(testServerIP4),
		store:      NewPeerStore(),
	}
	_, err := svc.allocateIPs([]string{FamilyIPv4})
	if err == nil {
		t.Fatal("expected error when device is unavailable")
	}
}

// ---------- rotatePeer via EnsurePeer ----------

func TestEnsurePeerRotateDeviceError(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}, configureErr: errors.New(testErrDeviceBusyMessage)},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(testServerIP4),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       "rotate-fail",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
	})

	_, err := svc.EnsurePeer("rotate-fail", nil, nil)
	if err == nil {
		t.Fatal("expected error when ConfigureDevice fails during rotation")
	}
}

func TestEnsurePeerRotateUpdatesExpiresAt(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(testServerIP4),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       testExpiryPeerID,
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
	})

	future := time.Now().UTC().Add(time.Hour)
	_, err := svc.EnsurePeer(testExpiryPeerID, &future, nil)
	if err != nil {
		t.Fatalf("EnsurePeer: %v", err)
	}
	rec, _ := svc.store.Get(testExpiryPeerID)
	if rec.ExpiresAt == nil || !rec.ExpiresAt.Equal(future) {
		t.Errorf("expected expiresAt to be updated to %v, got %v", future, rec.ExpiresAt)
	}
}

// ---------- Stats with IPv6 ----------

func TestStatsBothSubnets(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	device := &wgtypes.Device{ListenPort: 51820}
	svc := &WireGuardService{
		client:     fakeWGClient{device: device},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(testServerIP4),
		subnet6:    subnet6,
		serverIP6:  net.ParseIP(testServerIP6),
		store:      NewPeerStore(),
	}
	stats, err := svc.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if len(stats.WireGuard.Subnets) != 2 {
		t.Errorf("expected 2 subnets, got %d: %v", len(stats.WireGuard.Subnets), stats.WireGuard.Subnets)
	}
	if len(stats.WireGuard.AddressFamilies) != 2 {
		t.Errorf("expected 2 address families, got %d", len(stats.WireGuard.AddressFamilies))
	}
}

func TestStatsDeviceError(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	svc := &WireGuardService{
		client:     fakeWGClient{err: errors.New(testErrDeviceError)},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(testServerIP4),
		store:      NewPeerStore(),
	}
	_, err := svc.Stats()
	if err == nil {
		t.Fatal("expected error when device is unavailable")
	}
}

// ---------- ListPeers ----------

func TestListPeersDeviceError(t *testing.T) {
	svc := &WireGuardService{
		client:     fakeWGClient{err: errors.New(testErrDeviceError)},
		deviceName: "wg0",
		store:      NewPeerStore(),
	}
	_, err := svc.ListPeers()
	if err == nil {
		t.Fatal("expected error when device is unavailable")
	}
}

func TestListPeersActivePeer(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	key, _ := wgtypes.GenerateKey()
	recentHandshake := time.Now().Add(-30 * time.Second)
	device := &wgtypes.Device{
		Peers: []wgtypes.Peer{
			{PublicKey: key, LastHandshakeTime: recentHandshake},
		},
	}
	svc := &WireGuardService{
		client:     fakeWGClient{device: device},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(testServerIP4),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       "active-peer",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
		CreatedAt:    time.Now().UTC(),
	})

	list, err := svc.ListPeers()
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(list))
	}
	if !list[0].Active {
		t.Error("peer should be active (recent handshake)")
	}
}

// ---------- peerRecordToListItem ----------

func TestPeerRecordToListItemActiveState(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	rec := PeerRecord{
		PeerID:       "p1",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
		CreatedAt:    time.Now().UTC(),
	}
	recentHandshake := time.Now().Add(-30 * time.Second)
	devicePeer := wgtypes.Peer{PublicKey: key, LastHandshakeTime: recentHandshake}

	item := peerRecordToListItem(rec, devicePeer, time.Now())
	if !item.Active {
		t.Error("expected peer to be active")
	}
	if item.LastHandshakeAt == nil {
		t.Error("expected non-nil LastHandshakeAt")
	}
}

func TestPeerRecordToListItemInactiveState(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	rec := PeerRecord{
		PeerID:       "p2",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
		CreatedAt:    time.Now().UTC(),
	}
	oldHandshake := time.Now().Add(-10 * time.Minute)
	devicePeer := wgtypes.Peer{PublicKey: key, LastHandshakeTime: oldHandshake}

	item := peerRecordToListItem(rec, devicePeer, time.Now())
	if item.Active {
		t.Error("expected peer to be inactive (old handshake)")
	}
	if item.LastHandshakeAt == nil {
		t.Error("expected non-nil LastHandshakeAt for old handshake")
	}
}

func TestPeerRecordToListItemNoHandshake(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	rec := PeerRecord{
		PeerID:       "p3",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
	}
	item := peerRecordToListItem(rec, wgtypes.Peer{}, time.Now())
	if item.Active {
		t.Error("expected peer to be inactive (no handshake)")
	}
	if item.LastHandshakeAt != nil {
		t.Error("expected nil LastHandshakeAt when never connected")
	}
	if item.CreatedAt != "" {
		t.Error("expected empty createdAt for zero time")
	}
}

func TestPeerRecordToListItemIPv6Family(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	rec := PeerRecord{
		PeerID:       "p4",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4, "fd00::2/128"),
		CreatedAt:    time.Now().UTC(),
	}
	item := peerRecordToListItem(rec, wgtypes.Peer{}, time.Now())
	if len(item.AddressFamilies) != 2 {
		t.Errorf("expected 2 families, got %v", item.AddressFamilies)
	}
}

// ---------- ValidateAddressFamilies ----------

func TestValidateAddressFamiliesBothFamilies(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{
		subnet4:   subnet4,
		serverIP4: net.ParseIP(testServerIP4),
		subnet6:   subnet6,
		serverIP6: net.ParseIP(testServerIP6),
		store:     NewPeerStore(),
	}
	families, err := svc.ValidateAddressFamilies([]string{FamilyIPv4, FamilyIPv6})
	if err != nil {
		t.Fatalf(testErrUnexpectedFormat, err)
	}
	if len(families) != 2 {
		t.Errorf(msgExpectedTwoFamilies, families)
	}
}

func TestValidateAddressFamiliesIPv4OnlyNode(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	svc := &WireGuardService{
		subnet4:   subnet4,
		serverIP4: net.ParseIP(testServerIP4),
		store:     NewPeerStore(),
	}
	// Requesting IPv6 from IPv4-only node
	_, err := svc.ValidateAddressFamilies([]string{FamilyIPv6})
	if !errors.Is(err, ErrUnsupportedAddressFamily) {
		t.Fatalf("expected ErrUnsupportedAddressFamily, got %v", err)
	}
}

// ---------- DeletePeer ----------

func TestDeletePeerDeviceError(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}, configureErr: errors.New("device busy")},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(testServerIP4),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       testDelFailPeerID,
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
	})

	if err := svc.DeletePeer(testDelFailPeerID); err == nil {
		t.Fatal("expected error when ConfigureDevice fails")
	}
	// Peer should still be in store since device removal failed
	if _, ok := svc.store.Get(testDelFailPeerID); !ok {
		t.Error("peer should remain in store when device removal fails")
	}
}

// ---------- ServerInfo error ----------

func TestServerInfoDeviceError(t *testing.T) {
	svc := &WireGuardService{
		client:     fakeWGClient{err: errors.New(testErrDeviceOffline)},
		deviceName: "wg0",
		store:      NewPeerStore(),
	}
	_, _, err := svc.ServerInfo()
	if err == nil {
		t.Fatal("expected error when device is unavailable")
	}
}

// ---------- ValidateAddressFamilies edge cases ----------

func TestValidateAddressFamiliesInvalidFamilyName(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	svc := &WireGuardService{subnet4: subnet4, store: NewPeerStore()}
	_, err := svc.ValidateAddressFamilies([]string{"InvalidFamily"})
	if err == nil {
		t.Fatal("expected error for unknown address family")
	}
}

func TestValidateAddressFamiliesDuplicateFamily(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{subnet4: subnet4, subnet6: subnet6, store: NewPeerStore()}
	_, err := svc.ValidateAddressFamilies([]string{FamilyIPv4, FamilyIPv4})
	if err == nil {
		t.Fatal("expected error for duplicate address family")
	}
}

// ---------- resolveServerIP4 edge cases ----------

func TestResolveServerIP4IPv6Input(t *testing.T) {
	_, subnet, _ := net.ParseCIDR(testSubnet4)
	_, err := resolveServerIP4(subnet, "fd00::1")
	if err == nil {
		t.Fatal("expected error for IPv6 address passed as server_ip")
	}
}

// ---------- NodeAddressFamilies ----------

func TestNodeAddressFamiliesDualStack(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(testSubnet4)
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{subnet4: subnet4, subnet6: subnet6}
	families := svc.NodeAddressFamilies()
	if len(families) != 2 {
		t.Errorf("expected 2 families, got %v", families)
	}
}
