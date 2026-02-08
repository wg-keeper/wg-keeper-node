package wireguard

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/wg-keeper/wg-keeper-node/internal/config"
	"github.com/wg-keeper/wg-keeper-node/internal/version"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	ErrPeerNotFound  = errors.New("peer not found")
	ErrNoAvailableIP = errors.New("no available ip addresses")
)

const activePeerWindow = 2 * time.Minute

var serverStart = time.Now()

type PeerInfo struct {
	PeerID       string
	PublicKey    string
	PrivateKey   string
	PresharedKey string
	AllowedIP    string
}

type WireGuardService struct {
	client     wgClient
	deviceName string
	subnet     *net.IPNet
	serverIP   net.IP
	store      *PeerStore
}

type wgClient interface {
	Device(string) (*wgtypes.Device, error)
	ConfigureDevice(string, wgtypes.Config) error
}

type Stats struct {
	Service   ServiceInfo   `json:"service"`
	WireGuard WireGuardInfo `json:"wireguard"`
	Peers     PeerStats     `json:"peers"`
	StartedAt string        `json:"startedAt"`
}

type ServiceInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type PeerStats struct {
	Possible int `json:"possible"`
	Issued   int `json:"issued"`
	Active   int `json:"active"`
}

type WireGuardInfo struct {
	Interface  string `json:"interface"`
	ListenPort int    `json:"listenPort"`
	Subnet     string `json:"subnet"`
	ServerIP   string `json:"serverIp"`
}

// PeerListItem is a minimal peer entry for list responses.
type PeerListItem struct {
	PeerID           string     `json:"peerId"`
	AllowedIP        string     `json:"allowedIP"`
	PublicKey        string     `json:"publicKey"`
	Active           bool       `json:"active"`
	LastHandshakeAt  *time.Time `json:"lastHandshakeAt"`
	CreatedAt        string     `json:"createdAt"`
}

// PeerDetail extends PeerListItem with traffic stats for single-peer responses.
type PeerDetail struct {
	PeerListItem
	ReceiveBytes  int64 `json:"receiveBytes"`
	TransmitBytes int64 `json:"transmitBytes"`
}

func NewWireGuardService(cfg config.Config) (*WireGuardService, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	_, subnet, err := net.ParseCIDR(cfg.WGSubnet)
	if err != nil {
		return nil, fmt.Errorf("invalid WG_SUBNET: %w", err)
	}
	if subnet.IP.To4() == nil {
		return nil, errors.New("WG_SUBNET must be IPv4")
	}

	serverIP, err := resolveServerIP(subnet, cfg.WGServerIP)
	if err != nil {
		return nil, err
	}

	return &WireGuardService{
		client:     client,
		deviceName: cfg.WGInterface,
		subnet:     subnet,
		serverIP:   serverIP,
		store:      NewPeerStore(),
	}, nil
}

func (s *WireGuardService) EnsurePeer(peerID string) (PeerInfo, error) {
	if record, ok := s.store.Get(peerID); ok {
		return s.rotatePeer(peerID, record)
	}

	allowedIP, err := s.allocateIP()
	if err != nil {
		return PeerInfo{}, err
	}

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return PeerInfo{}, err
	}

	publicKey := privateKey.PublicKey()
	presharedKey, err := wgtypes.GenerateKey()
	if err != nil {
		return PeerInfo{}, err
	}
	peerConfig := wgtypes.PeerConfig{
		PublicKey:                   publicKey,
		PresharedKey:                &presharedKey,
		AllowedIPs:                  []net.IPNet{allowedIP},
		ReplaceAllowedIPs:           true,
		PersistentKeepaliveInterval: keepaliveInterval(),
	}

	if err := s.client.ConfigureDevice(s.deviceName, wgtypes.Config{Peers: []wgtypes.PeerConfig{peerConfig}}); err != nil {
		return PeerInfo{}, err
	}

	s.store.Set(PeerRecord{
		PeerID:    peerID,
		PublicKey: publicKey,
		AllowedIP: allowedIP,
		CreatedAt: time.Now().UTC(),
	})

	return PeerInfo{
		PeerID:       peerID,
		PublicKey:    publicKey.String(),
		PrivateKey:   privateKey.String(),
		PresharedKey: presharedKey.String(),
		AllowedIP:    allowedIP.String(),
	}, nil
}

func (s *WireGuardService) ServerInfo() (string, int, error) {
	device, err := s.client.Device(s.deviceName)
	if err != nil {
		return "", 0, err
	}
	return device.PublicKey.String(), device.ListenPort, nil
}

func (s *WireGuardService) DeletePeer(peerID string) error {
	record, ok := s.store.Get(peerID)
	if !ok {
		return ErrPeerNotFound
	}

	remove := wgtypes.PeerConfig{
		PublicKey: record.PublicKey,
		Remove:    true,
	}

	if err := s.client.ConfigureDevice(s.deviceName, wgtypes.Config{Peers: []wgtypes.PeerConfig{remove}}); err != nil {
		return err
	}

	s.store.Delete(peerID)
	return nil
}

func (s *WireGuardService) Stats() (Stats, error) {
	peersPossible, err := possiblePeerCount(s.subnet, s.serverIP)
	if err != nil {
		return Stats{}, err
	}

	device, err := s.client.Device(s.deviceName)
	if err != nil {
		return Stats{}, err
	}

	now := time.Now()
	active := 0
	for _, peer := range device.Peers {
		if peer.LastHandshakeTime.IsZero() {
			continue
		}
		if now.Sub(peer.LastHandshakeTime) <= activePeerWindow {
			active++
		}
	}

	return Stats{
		Service: ServiceInfo{
			Name:    version.Name,
			Version: version.Version,
		},
		WireGuard: WireGuardInfo{
			Interface:  s.deviceName,
			ListenPort: device.ListenPort,
			Subnet:     s.subnet.String(),
			ServerIP:   s.serverIP.String(),
		},
		Peers: PeerStats{
			Possible: peersPossible,
			Issued:   len(s.store.List()),
			Active:   active,
		},
		StartedAt: serverStart.UTC().Format(time.RFC3339),
	}, nil
}

func (s *WireGuardService) ListPeers() ([]PeerListItem, error) {
	device, err := s.client.Device(s.deviceName)
	if err != nil {
		return nil, err
	}
	devicePeerByKey := make(map[wgtypes.Key]wgtypes.Peer)
	for _, p := range device.Peers {
		devicePeerByKey[p.PublicKey] = p
	}

	now := time.Now()
	list := make([]PeerListItem, 0, len(s.store.List()))
	for _, rec := range s.store.List() {
		item := peerRecordToListItem(rec, devicePeerByKey[rec.PublicKey], now)
		list = append(list, item)
	}
	return list, nil
}

func (s *WireGuardService) GetPeer(peerID string) (*PeerDetail, error) {
	record, ok := s.store.Get(peerID)
	if !ok {
		return nil, ErrPeerNotFound
	}
	device, err := s.client.Device(s.deviceName)
	if err != nil {
		return nil, err
	}
	var devicePeer wgtypes.Peer
	for i := range device.Peers {
		if device.Peers[i].PublicKey == record.PublicKey {
			devicePeer = device.Peers[i]
			break
		}
	}
	now := time.Now()
	item := peerRecordToListItem(record, devicePeer, now)
	detail := &PeerDetail{
		PeerListItem:   item,
		ReceiveBytes:  devicePeer.ReceiveBytes,
		TransmitBytes: devicePeer.TransmitBytes,
	}
	return detail, nil
}

func peerRecordToListItem(rec PeerRecord, devicePeer wgtypes.Peer, now time.Time) PeerListItem {
	var lastHandshake *time.Time
	active := false
	if !devicePeer.LastHandshakeTime.IsZero() {
		t := devicePeer.LastHandshakeTime
		lastHandshake = &t
		if now.Sub(devicePeer.LastHandshakeTime) <= activePeerWindow {
			active = true
		}
	}
	createdAt := rec.CreatedAt.UTC().Format(time.RFC3339)
	if rec.CreatedAt.IsZero() {
		createdAt = ""
	}
	return PeerListItem{
		PeerID:          rec.PeerID,
		AllowedIP:       rec.AllowedIP.String(),
		PublicKey:       rec.PublicKey.String(),
		Active:          active,
		LastHandshakeAt: lastHandshake,
		CreatedAt:       createdAt,
	}
}

func (s *WireGuardService) rotatePeer(peerID string, record PeerRecord) (PeerInfo, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return PeerInfo{}, err
	}

	publicKey := privateKey.PublicKey()
	presharedKey, err := wgtypes.GenerateKey()
	if err != nil {
		return PeerInfo{}, err
	}
	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: record.PublicKey,
				Remove:    true,
			},
			{
				PublicKey:                   publicKey,
				PresharedKey:                &presharedKey,
				AllowedIPs:                  []net.IPNet{record.AllowedIP},
				ReplaceAllowedIPs:           true,
				PersistentKeepaliveInterval: keepaliveInterval(),
			},
		},
	}

	if err := s.client.ConfigureDevice(s.deviceName, config); err != nil {
		return PeerInfo{}, err
	}

	s.store.Set(PeerRecord{
		PeerID:    peerID,
		PublicKey: publicKey,
		AllowedIP: record.AllowedIP,
		CreatedAt: record.CreatedAt,
	})

	return PeerInfo{
		PeerID:       peerID,
		PublicKey:    publicKey.String(),
		PrivateKey:   privateKey.String(),
		PresharedKey: presharedKey.String(),
		AllowedIP:    record.AllowedIP.String(),
	}, nil
}

func (s *WireGuardService) allocateIP() (net.IPNet, error) {
	used := make(map[string]struct{})
	used[s.serverIP.String()] = struct{}{}

	for _, record := range s.store.List() {
		used[record.AllowedIP.IP.String()] = struct{}{}
	}

	device, err := s.client.Device(s.deviceName)
	if err != nil {
		return net.IPNet{}, err
	}
	for _, peer := range device.Peers {
		for _, allowed := range peer.AllowedIPs {
			if allowed.IP.To4() != nil {
				used[allowed.IP.String()] = struct{}{}
			}
		}
	}

	start, end, err := ipv4Range(s.subnet)
	if err != nil {
		return net.IPNet{}, err
	}

	for ip := start; !ipAfter(ip, end); ip = nextIPv4(ip) {
		if _, exists := used[ip.String()]; exists {
			continue
		}
		return net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
	}

	return net.IPNet{}, ErrNoAvailableIP
}

func resolveServerIP(subnet *net.IPNet, serverIP string) (net.IP, error) {
	if serverIP != "" {
		ip := net.ParseIP(serverIP)
		if ip == nil || ip.To4() == nil {
			return nil, errors.New("WG_SERVER_IP must be a valid IPv4 address")
		}
		if !subnet.Contains(ip) {
			return nil, errors.New("WG_SERVER_IP must be inside WG_SUBNET")
		}
		return ip.To4(), nil
	}

	start, _, err := ipv4Range(subnet)
	if err != nil {
		return nil, err
	}
	return start, nil
}

func ipv4Range(subnet *net.IPNet) (net.IP, net.IP, error) {
	network := subnet.IP.Mask(subnet.Mask).To4()
	if network == nil {
		return nil, nil, errors.New("WG_SUBNET must be IPv4")
	}

	mask := net.IP(subnet.Mask).To4()
	if mask == nil {
		return nil, nil, errors.New("WG_SUBNET mask must be IPv4")
	}

	networkInt := ipToUint32(network)
	maskInt := ipToUint32(mask)
	broadcast := networkInt | ^maskInt

	start := networkInt + 1
	end := broadcast - 1
	if end < start {
		return nil, nil, errors.New("WG_SUBNET is too small")
	}

	return uint32ToIP(start), uint32ToIP(end), nil
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(value uint32) net.IP {
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

func nextIPv4(ip net.IP) net.IP {
	return uint32ToIP(ipToUint32(ip) + 1)
}

func ipAfter(a, b net.IP) bool {
	return ipToUint32(a) > ipToUint32(b)
}

func keepaliveInterval() *time.Duration {
	interval := 25 * time.Second
	return &interval
}

func possiblePeerCount(subnet *net.IPNet, serverIP net.IP) (int, error) {
	start, end, err := ipv4Range(subnet)
	if err != nil {
		return 0, err
	}

	startInt := ipToUint32(start)
	endInt := ipToUint32(end)
	if endInt < startInt {
		return 0, nil
	}
	total := int(endInt-startInt) + 1

	if serverIP != nil {
		serverIPv4 := serverIP.To4()
		if serverIPv4 != nil {
			serverInt := ipToUint32(serverIPv4)
			if serverInt >= startInt && serverInt <= endInt {
				total--
			}
		}
	}

	if total < 0 {
		return 0, nil
	}
	return total, nil
}
