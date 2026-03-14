package wireguard

import (
	"errors"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// subnetTestCIDR, ipServerTest, msgUnexpectedError — from wireguard_test.go (same package)
// subnet6TestCIDR, subnet6TestCIDR64, ipv6TestAddr1  — from wireguard_ipv6_test.go (same package)
const (
	testSubnet31       = "10.0.0.0/31"
	testSubnet6        = "fd00::/112"
	testServerIP6InBig = "fd00::5"
	testServerIP6Out   = "fd01::1"

	testPeerIP4              = "10.0.0.2/32"
	testOutsidePeerID        = "outside-peer"
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
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
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
		serverIP6:  net.ParseIP(ipv6TestAddr1),
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
	_, subnet31, _ := net.ParseCIDR(testSubnet31)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet31,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	_, err := svc.allocateIPs([]string{FamilyIPv4})
	if err == nil {
		t.Fatal("expected error from allocateOneIPv4 for /31 subnet")
	}
}

// ---------- allocateOneIPv6 with large subnet (ones < 112) ----------

func TestAllocateOneIPv6LargeSubnet(t *testing.T) {
	_, subnet, _ := net.ParseCIDR(subnet6TestCIDR64) // /64, ones=64 < 112
	used := map[string]struct{}{}
	ipNet, err := allocateOneIPv6(subnet, used, nil)
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
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
	_, subnet31, _ := net.ParseCIDR(testSubnet31)
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
	_, subnet31, _ := net.ParseCIDR(testSubnet31)
	svc := &WireGuardService{subnet4: subnet31, store: NewPeerStore()}
	_, err := svc.possiblePeerCountTotal()
	if err == nil {
		t.Fatal("expected error for /31 subnet in possiblePeerCountTotal")
	}
}

func TestEnsurePeerConfigureDeviceError(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}, configureErr: errors.New(testErrDeviceBusyMessage)},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
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
	sub, ip, err := setupSubnet4(subnetTestCIDR, "")
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if sub == nil || ip == nil {
		t.Fatal("expected non-nil subnet and server IP")
	}
	if ip.String() != ipServerTest {
		t.Errorf("expected default server IP %s, got %s", ipServerTest, ip.String())
	}
}

func TestSetupSubnet4InvalidCIDR(t *testing.T) {
	if _, _, err := setupSubnet4("not-a-cidr", ""); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestSetupSubnet4IPv6Rejected(t *testing.T) {
	if _, _, err := setupSubnet4(subnet6TestCIDR64, ""); err == nil {
		t.Fatal("expected error for IPv6 passed as subnet4")
	}
}

func TestSetupSubnet4ServerIPOutsideSubnet(t *testing.T) {
	if _, _, err := setupSubnet4(subnetTestCIDR, "192.168.1.1"); err == nil {
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
		t.Fatalf(msgUnexpectedError, err)
	}
	if sub == nil || ip == nil {
		t.Fatal("expected non-nil subnet and server IP")
	}
}

func TestSetupSubnet6IPv4Rejected(t *testing.T) {
	if _, _, err := setupSubnet6(subnetTestCIDR, ""); err == nil {
		t.Fatal("expected error for IPv4 passed as subnet6")
	}
}

// ---------- reconcileStoreWithSubnets ----------

func TestReconcileStoreWithSubnetsPeerInsideKept(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
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
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
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
	// ConfigureDevice fails: peer must NOT be removed from the store to keep
	// store and device in sync. Removing the store record while the peer still
	// exists on the device would create an orphan invisible to the application.
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}, configureErr: errors.New("device busy")},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       testOutsidePeerID,
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, "192.168.1.5/32"),
	})

	changed := svc.reconcileStoreWithSubnets()
	if changed {
		t.Error("expected changed=false: store removal must be skipped when device removal fails")
	}
	if _, ok := svc.store.Get(testOutsidePeerID); !ok {
		t.Error("peer must remain in store when device removal fails to keep store and device in sync")
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
	_, subnet, _ := net.ParseCIDR(subnet6TestCIDR64)
	n, err := possiblePeerCountIPv6(subnet, nil)
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if n != maxIPv6PeersReported {
		t.Errorf("expected cap of %d, got %d", maxIPv6PeersReported, n)
	}
}

func TestPossiblePeerCountIPv6LargeSubnetServerIPInRange(t *testing.T) {
	// server IP is inside the large subnet → count decremented by 1
	_, subnet, _ := net.ParseCIDR(subnet6TestCIDR64)
	serverIP := net.ParseIP(testServerIP6InBig)
	n, err := possiblePeerCountIPv6(subnet, serverIP)
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if n != maxIPv6PeersReported-1 {
		t.Errorf("expected %d (server IP deducted), got %d", maxIPv6PeersReported-1, n)
	}
}

func TestPossiblePeerCountIPv6LargeSubnetServerIPOutsideRange(t *testing.T) {
	// server IP is outside the subnet → count stays at cap
	_, subnet, _ := net.ParseCIDR(subnet6TestCIDR64)
	serverIP := net.ParseIP(testServerIP6Out) // different prefix
	n, err := possiblePeerCountIPv6(subnet, serverIP)
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if n != maxIPv6PeersReported {
		t.Errorf("expected cap of %d, got %d", maxIPv6PeersReported, n)
	}
}

func TestPossiblePeerCountIPv6SmallSubnetWithServerIP(t *testing.T) {
	// /120 (ones=120 ≥ 112) → iterates; server IP is excluded
	_, subnet, _ := net.ParseCIDR(subnet6TestCIDR)
	serverIP := net.ParseIP(ipv6TestAddr1)
	n, err := possiblePeerCountIPv6(subnet, serverIP)
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	// /120 = 256 addresses, 2 reserved (start/end), server excluded → 253
	withoutServer, _ := possiblePeerCountIPv6(subnet, nil)
	if n != withoutServer-1 {
		t.Errorf("expected server IP to reduce count by 1: without=%d with=%d", withoutServer, n)
	}
}

// ---------- possiblePeerCountTotal ----------

func TestPossiblePeerCountTotalDualStack(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{
		subnet4:   subnet4,
		serverIP4: net.ParseIP(ipServerTest),
		subnet6:   subnet6,
		serverIP6: net.ParseIP(ipv6TestAddr1),
		store:     NewPeerStore(),
	}
	n, err := svc.possiblePeerCountTotal()
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	v4, _ := possiblePeerCount(subnet4, net.ParseIP(ipServerTest))
	v6, _ := possiblePeerCountIPv6(subnet6, net.ParseIP(ipv6TestAddr1))
	if n != v4+v6 {
		t.Errorf("expected %d+%d=%d, got %d", v4, v6, v4+v6, n)
	}
}

func TestPossiblePeerCountTotalIPv6Only(t *testing.T) {
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{
		subnet6:   subnet6,
		serverIP6: net.ParseIP(ipv6TestAddr1),
		store:     NewPeerStore(),
	}
	n, err := svc.possiblePeerCountTotal()
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
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
		serverIP6:  net.ParseIP(ipv6TestAddr1),
		store:      NewPeerStore(),
	}
	ips, err := svc.allocateIPs([]string{FamilyIPv6})
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips))
	}
	if ips[0].IP.To4() != nil {
		t.Error("expected IPv6 address, got IPv4")
	}
}

func TestAllocateIPsDualStack(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		subnet6:    subnet6,
		serverIP6:  net.ParseIP(ipv6TestAddr1),
		store:      NewPeerStore(),
	}
	ips, err := svc.allocateIPs([]string{FamilyIPv4, FamilyIPv6})
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs (one per family), got %d", len(ips))
	}
}

// ---------- rotatePeer via EnsurePeer ----------

func TestEnsurePeerRotateDeviceError(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}, configureErr: errors.New(testErrDeviceBusyMessage)},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
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
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
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
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	device := &wgtypes.Device{ListenPort: 51820}
	svc := &WireGuardService{
		client:     fakeWGClient{device: device},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		subnet6:    subnet6,
		serverIP6:  net.ParseIP(ipv6TestAddr1),
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
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{
		client:     fakeWGClient{err: errors.New(testErrDeviceError)},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
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
	_, _, err := svc.ListPeers(0, 0)
	if err == nil {
		t.Fatal("expected error when device is unavailable")
	}
}

func TestListPeersActivePeer(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
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
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       "active-peer",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
		CreatedAt:    time.Now().UTC(),
	})

	list, _, err := svc.ListPeers(0, 0)
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
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{
		subnet4:   subnet4,
		serverIP4: net.ParseIP(ipServerTest),
		subnet6:   subnet6,
		serverIP6: net.ParseIP(ipv6TestAddr1),
		store:     NewPeerStore(),
	}
	families, err := svc.ValidateAddressFamilies([]string{FamilyIPv4, FamilyIPv6})
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if len(families) != 2 {
		t.Errorf(msgExpectedTwoFamilies, families)
	}
}

func TestValidateAddressFamiliesIPv4OnlyNode(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{
		subnet4:   subnet4,
		serverIP4: net.ParseIP(ipServerTest),
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
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}, configureErr: errors.New("device busy")},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
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
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{subnet4: subnet4, store: NewPeerStore()}
	_, err := svc.ValidateAddressFamilies([]string{"InvalidFamily"})
	if err == nil {
		t.Fatal("expected error for unknown address family")
	}
}

func TestValidateAddressFamiliesDuplicateFamily(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{subnet4: subnet4, subnet6: subnet6, store: NewPeerStore()}
	_, err := svc.ValidateAddressFamilies([]string{FamilyIPv4, FamilyIPv4})
	if err == nil {
		t.Fatal("expected error for duplicate address family")
	}
}

// ---------- resolveServerIP4 edge cases ----------

func TestResolveServerIP4IPv6Input(t *testing.T) {
	_, subnet, _ := net.ParseCIDR(subnetTestCIDR)
	_, err := resolveServerIP4(subnet, ipv6TestAddr1)
	if err == nil {
		t.Fatal("expected error for IPv6 address passed as server_ip")
	}
}

// ---------- NodeAddressFamilies ----------

func TestNodeAddressFamiliesDualStack(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{subnet4: subnet4, subnet6: subnet6}
	families := svc.NodeAddressFamilies()
	if len(families) != 2 {
		t.Errorf("expected 2 families, got %v", families)
	}
}

// ---------- prevIPv6 ----------

func TestPrevIPv6(t *testing.T) {
	cases := []struct{ in, want string }{
		{"fd00::5", "fd00::4"},
		{"fd00::100", "fd00::ff"},
		{ipv6TestAddr1, "fd00::"},
	}
	for _, tc := range cases {
		got := prevIPv6(net.ParseIP(tc.in))
		if got.String() != tc.want {
			t.Errorf("prevIPv6(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// ---------- ipv6SearchFrom ----------

func TestIPv6SearchFromHintOutOfRange(t *testing.T) {
	_, subnet, _ := net.ParseCIDR(subnet6TestCIDR) // fd00::/120
	start, end, _ := ipv6Range(subnet)             // fd00::1 .. fd00::fe

	// hint before start
	h1 := net.ParseIP("fd00::").To16()
	if from := ipv6SearchFrom(start, end, &h1); !from.Equal(start) {
		t.Errorf("hint before start: expected start, got %s", from)
	}
	// hint after end
	h2 := net.ParseIP("fd00::ff").To16()
	if from := ipv6SearchFrom(start, end, &h2); !from.Equal(start) {
		t.Errorf("hint after end: expected start, got %s", from)
	}
}

func TestIPv6SearchFromHintAtEnd(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("fd00::/126") // fd00::1 .. fd00::2
	start, end, _ := ipv6Range(subnet)

	// hint = end: next overflows past end → searchFrom wraps to start
	h := make(net.IP, 16)
	copy(h, end)
	from := ipv6SearchFrom(start, end, &h)
	if !from.Equal(start) {
		t.Errorf("hint at end: expected wrap to start, got %s", from)
	}
}

// ---------- allocateOneIPv4 wrap-around ----------

func TestAllocateOneIPv4WrapAround(t *testing.T) {
	// /30: usable range 10.0.0.1 – 10.0.0.2 (2 IPs)
	_, subnet, _ := net.ParseCIDR("10.0.0.0/30")
	used := map[string]struct{}{"10.0.0.2": {}}
	hint := ipToUint32(net.ParseIP(ipServerTest).To4()) // searchFrom = .2
	ipNet, err := allocateOneIPv4(subnet, used, &hint)
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if ipNet.IP.String() != ipServerTest {
		t.Errorf("expected 10.0.0.1 (wrap-around), got %s", ipNet.IP)
	}
}

// ---------- allocateOneIPv6 wrap-around (also exercises prevIPv6) ----------

func TestAllocateOneIPv6WrapAround(t *testing.T) {
	// fd00::/126: usable fd00::1 – fd00::2
	_, subnet, _ := net.ParseCIDR("fd00::/126")
	used := map[string]struct{}{"fd00::2": {}}
	hint := net.ParseIP(ipv6TestAddr1).To16() // searchFrom = fd00::2
	ipNet, err := allocateOneIPv6(subnet, used, &hint)
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if ipNet.IP.String() != ipv6TestAddr1 {
		t.Errorf("expected fd00::1 (wrap-around), got %s", ipNet.IP)
	}
}

// ---------- large IPv4 subnet triggers maxIter cap ----------

func TestAllocateOneIPv4LargeSubnetCap(t *testing.T) {
	// /15 has 131070 usable IPs → triggers maxIter = maxIPv4Iter
	_, subnet, _ := net.ParseCIDR("10.0.0.0/15")
	used := make(map[string]struct{})
	hint := uint32(0)
	ipNet, err := allocateOneIPv4(subnet, used, &hint)
	if err != nil {
		t.Fatalf("unexpected error for large subnet: %v", err)
	}
	if ipNet.IP == nil {
		t.Fatal("expected non-nil IP")
	}
}

// ---------- scanIPv4Range / scanIPv6Range maxIter exceeded ----------

func TestScanIPv4RangeMaxIterExceeded(t *testing.T) {
	used := map[string]struct{}{}
	n := 5
	from := ipToUint32(net.ParseIP(ipServerTest).To4())
	to := ipToUint32(net.ParseIP("10.0.0.10").To4())
	if _, ok := scanIPv4Range(from, to, 5, &n, used, nil); ok {
		t.Fatal("expected false when n already >= maxIter")
	}
}

func TestScanIPv6RangeMaxIterExceeded(t *testing.T) {
	used := map[string]struct{}{}
	n := 5
	from := net.ParseIP(ipv6TestAddr1).To16()
	to := net.ParseIP("fd00::10").To16()
	if _, ok := scanIPv6Range(from, to, 5, &n, used, nil); ok {
		t.Fatal("expected false when n already >= maxIter")
	}
}

// ---------- cleanup updates usedIPs ----------

func TestCleanupExpiredPeerUpdatesUsedIPs(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	expiredAt := time.Now().UTC().Add(-time.Hour)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.initUsedIPs()
	svc.store.Set(PeerRecord{
		PeerID:     "expiring",
		PublicKey:  key,
		AllowedIPs: []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  &expiredAt,
	})
	svc.usedIPs[ipPeerTest] = struct{}{}

	svc.cleanupExpiredPeers()

	if _, ok := svc.usedIPs[ipPeerTest]; ok {
		t.Error("expected IP to be removed from usedIPs after expiry cleanup")
	}
}

// ---------- deleteExpiredPeerLocked race guard ----------

// TestDeleteExpiredPeerLockedExtended verifies that deleteExpiredPeerLocked returns
// (false, nil) when the peer's expiry was extended between the ForEach snapshot and
// the lock acquisition (simulated by storing a future ExpiresAt before calling directly).
func TestDeleteExpiredPeerLockedExtended(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	future := time.Now().UTC().Add(time.Hour)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       "ext-peer",
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    &future, // extended: ExpiresAt is in the future
	})

	deleted, err := svc.deleteExpiredPeerLocked("ext-peer", time.Now().UTC())
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if deleted {
		t.Fatal("expected deleted=false for peer whose expiry was extended")
	}
}

// TestDeleteExpiredPeerLockedMadePermanent verifies that deleteExpiredPeerLocked returns
// (false, nil) when the peer was made permanent (ExpiresAt set to nil) concurrently.
func TestDeleteExpiredPeerLockedMadePermanent(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       "perm-peer",
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    nil, // permanent peer
	})

	deleted, err := svc.deleteExpiredPeerLocked("perm-peer", time.Now().UTC())
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if deleted {
		t.Fatal("expected deleted=false for permanent peer")
	}
}
