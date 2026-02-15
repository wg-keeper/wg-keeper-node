package wireguard

import (
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// FakeClient is a wgClient implementation for tests. Use NewTestService to build
// a WireGuardService that uses it (e.g. for server router integration tests).
type FakeClient struct {
	Dev *wgtypes.Device
	Err error
}

// Device implements wgClient.
func (f FakeClient) Device(_ string) (*wgtypes.Device, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	if f.Dev == nil {
		return &wgtypes.Device{}, nil
	}
	return f.Dev, nil
}

// ConfigureDevice implements wgClient.
func (f FakeClient) ConfigureDevice(_ string, _ wgtypes.Config) error {
	return nil
}

// NewTestService returns a WireGuardService suitable for tests (in-memory store,
// fake wg client, minimal subnet so Stats works). Use it from server package for
// router integration tests.
func NewTestService() *WireGuardService {
	_, subnet4, _ := net.ParseCIDR("10.0.0.0/24")
	return &WireGuardService{
		client:     FakeClient{Dev: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP("10.0.0.1"),
		store:      NewPeerStore(),
	}
}
