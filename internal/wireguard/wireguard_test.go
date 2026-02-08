package wireguard

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	msgUnexpectedError = "unexpected error: %v"
	ipServerTest       = "10.0.0.1"
	ipPeerTest         = "10.0.0.2"
	peerIDTest         = "peer-1"
)

type fakeWGClient struct {
	device *wgtypes.Device
	err    error
}

func (f fakeWGClient) Device(_ string) (*wgtypes.Device, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.device, nil
}

func (f fakeWGClient) ConfigureDevice(_ string, _ wgtypes.Config) error {
	return nil
}

func ipNet(t *testing.T, ip string) net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(fmt.Sprintf("%s/32", ip))
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	return *n
}

func TestValidateAddressFamilies_EmptyReturnsNodeFamilies(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR("10.0.0.0/24")
	svc := &WireGuardService{subnet4: subnet4, serverIP4: net.ParseIP("10.0.0.1"), store: NewPeerStore()}
	families, err := svc.ValidateAddressFamilies(nil)
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if len(families) != 1 || families[0] != FamilyIPv4 {
		t.Fatalf("expected [IPv4], got %v", families)
	}
}

func TestValidateAddressFamilies_Unsupported(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR("10.0.0.0/24")
	svc := &WireGuardService{subnet4: subnet4, serverIP4: net.ParseIP("10.0.0.1"), store: NewPeerStore()}
	_, err := svc.ValidateAddressFamilies([]string{FamilyIPv6})
	if !errors.Is(err, ErrUnsupportedAddressFamily) {
		t.Fatalf("expected ErrUnsupportedAddressFamily, got %v", err)
	}
}

func TestResolveServerIP4(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.0.0.0/24")

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
