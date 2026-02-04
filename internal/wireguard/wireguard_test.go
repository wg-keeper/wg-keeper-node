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

func TestResolveServerIP(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.0.0.0/24")

	ip, err := resolveServerIP(subnet, "10.0.0.10")
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if ip.String() != "10.0.0.10" {
		t.Fatalf("unexpected ip: %s", ip.String())
	}

	if _, err := resolveServerIP(subnet, "10.0.1.10"); err == nil {
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
		subnet:     subnet,
		serverIP:   serverIP,
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:    peerIDTest,
		PublicKey: wgtypes.Key{},
		AllowedIP: ipNet(t, ipPeerTest),
	})

	ip, err := svc.allocateIP()
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if ip.IP.String() != "10.0.0.4" {
		t.Fatalf("expected 10.0.0.4, got %s", ip.IP.String())
	}
}

func TestAllocateIPNoAvailable(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.0.0.0/30")
	serverIP := net.ParseIP(ipServerTest)

	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet:     subnet,
		serverIP:   serverIP,
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:    peerIDTest,
		PublicKey: wgtypes.Key{},
		AllowedIP: ipNet(t, ipPeerTest),
	})

	_, err := svc.allocateIP()
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
		subnet:     subnet,
		serverIP:   serverIP,
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:    peerIDTest,
		PublicKey: wgtypes.Key{},
		AllowedIP: ipNet(t, ipPeerTest),
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
