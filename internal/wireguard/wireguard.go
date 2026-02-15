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

const (
	FamilyIPv4 = "IPv4"
	FamilyIPv6 = "IPv6"
)

var (
	ErrPeerNotFound             = errors.New("peer not found")
	ErrNoAvailableIP            = errors.New("no available ip addresses")
	ErrUnsupportedAddressFamily = errors.New("requested address family is not supported by this node")
)

const activePeerWindow = 2 * time.Minute

var serverStart = time.Now()

type PeerInfo struct {
	PeerID          string
	PublicKey       string
	PrivateKey      string
	PresharedKey    string
	AllowedIPs      []string // one per family (e.g. ["10.0.0.2/32", "fd00::2/128"])
	AddressFamilies []string // e.g. ["IPv4", "IPv6"] — what this peer has
}

type WireGuardService struct {
	client     wgClient
	deviceName string
	subnet4    *net.IPNet
	serverIP4  net.IP
	subnet6    *net.IPNet
	serverIP6  net.IP
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
	Interface       string   `json:"interface"`
	ListenPort      int      `json:"listenPort"`
	Subnets         []string `json:"subnets"`
	ServerIPs       []string `json:"serverIps"`
	AddressFamilies []string `json:"addressFamilies"` // what the node supports, e.g. ["IPv4", "IPv6"]
}

// PeerListItem is a minimal peer entry for list responses.
type PeerListItem struct {
	PeerID          string     `json:"peerId"`
	AllowedIPs      []string   `json:"allowedIPs"`
	AddressFamilies []string   `json:"addressFamilies"` // e.g. ["IPv4"] or ["IPv4", "IPv6"]
	PublicKey       string     `json:"publicKey"`
	Active          bool       `json:"active"`
	LastHandshakeAt *time.Time `json:"lastHandshakeAt"`
	CreatedAt       string     `json:"createdAt"`
	ExpiresAt       *string    `json:"expiresAt,omitempty"` // RFC3339, empty if permanent
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

	var subnet4, subnet6 *net.IPNet
	var serverIP4, serverIP6 net.IP

	if cfg.WGSubnet != "" {
		_, sub, err := net.ParseCIDR(cfg.WGSubnet)
		if err != nil {
			return nil, fmt.Errorf("invalid WG_SUBNET: %w", err)
		}
		if sub.IP.To4() == nil {
			return nil, errors.New("wireguard.subnet must be IPv4")
		}
		subnet4 = sub
		serverIP4, err = resolveServerIP4(subnet4, cfg.WGServerIP)
		if err != nil {
			return nil, err
		}
	}
	if cfg.WGSubnet6 != "" {
		_, sub, err := net.ParseCIDR(cfg.WGSubnet6)
		if err != nil {
			return nil, fmt.Errorf("invalid WG_SUBNET6: %w", err)
		}
		if sub.IP.To4() != nil {
			return nil, errors.New("wireguard.subnet6 must be IPv6")
		}
		subnet6 = sub
		serverIP6, err = resolveServerIP6(subnet6, cfg.WGServerIP6)
		if err != nil {
			return nil, err
		}
	}

	return &WireGuardService{
		client:     client,
		deviceName: cfg.WGInterface,
		subnet4:    subnet4,
		serverIP4:  serverIP4,
		subnet6:    subnet6,
		serverIP6:  serverIP6,
		store:      NewPeerStore(),
	}, nil
}

// NodeAddressFamilies returns the address families this node supports (e.g. ["IPv4", "IPv6"]).
func (s *WireGuardService) NodeAddressFamilies() []string {
	var out []string
	if s.subnet4 != nil {
		out = append(out, FamilyIPv4)
	}
	if s.subnet6 != nil {
		out = append(out, FamilyIPv6)
	}
	return out
}

// ValidateAddressFamilies checks that requested families are supported by the node.
// If requested is nil or empty, returns node's families (default = all). No duplicates allowed.
func (s *WireGuardService) ValidateAddressFamilies(requested []string) ([]string, error) {
	nodeFamilies := s.NodeAddressFamilies()
	if len(requested) == 0 {
		return nodeFamilies, nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, f := range requested {
		if f != FamilyIPv4 && f != FamilyIPv6 {
			return nil, fmt.Errorf("addressFamilies may only contain %q and %q", FamilyIPv4, FamilyIPv6)
		}
		if seen[f] {
			return nil, fmt.Errorf("duplicate address family %q", f)
		}
		seen[f] = true
		has := false
		for _, n := range nodeFamilies {
			if n == f {
				has = true
				break
			}
		}
		if !has {
			return nil, ErrUnsupportedAddressFamily
		}
		out = append(out, f)
	}
	return out, nil
}

func (s *WireGuardService) EnsurePeer(peerID string, expiresAt *time.Time, addressFamilies []string) (PeerInfo, error) {
	if record, ok := s.store.Get(peerID); ok {
		return s.rotatePeer(peerID, record, expiresAt)
	}

	families, err := s.ValidateAddressFamilies(addressFamilies)
	if err != nil {
		return PeerInfo{}, err
	}

	allowedIPs, err := s.allocateIPs(families)
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
		AllowedIPs:                  allowedIPs,
		ReplaceAllowedIPs:           true,
		PersistentKeepaliveInterval: keepaliveInterval(),
	}

	if err := s.client.ConfigureDevice(s.deviceName, wgtypes.Config{Peers: []wgtypes.PeerConfig{peerConfig}}); err != nil {
		return PeerInfo{}, err
	}

	s.store.Set(PeerRecord{
		PeerID:     peerID,
		PublicKey:  publicKey,
		AllowedIPs: allowedIPs,
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  expiresAt,
	})

	allowedIPsStr := make([]string, len(allowedIPs))
	for i := range allowedIPs {
		allowedIPsStr[i] = allowedIPs[i].String()
	}
	return PeerInfo{
		PeerID:          peerID,
		PublicKey:       publicKey.String(),
		PrivateKey:      privateKey.String(),
		PresharedKey:    presharedKey.String(),
		AllowedIPs:      allowedIPsStr,
		AddressFamilies: families,
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
	peersPossible, err := s.possiblePeerCountTotal()
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

	subnets := make([]string, 0, 2)
	serverIPs := make([]string, 0, 2)
	if s.subnet4 != nil {
		subnets = append(subnets, s.subnet4.String())
		serverIPs = append(serverIPs, s.serverIP4.String())
	}
	if s.subnet6 != nil {
		subnets = append(subnets, s.subnet6.String())
		serverIPs = append(serverIPs, s.serverIP6.String())
	}
	nodeFamilies := s.NodeAddressFamilies()

	return Stats{
		Service: ServiceInfo{
			Name:    version.Name,
			Version: version.Version,
		},
		WireGuard: WireGuardInfo{
			Interface:       s.deviceName,
			ListenPort:      device.ListenPort,
			Subnets:         subnets,
			ServerIPs:       serverIPs,
			AddressFamilies: nodeFamilies,
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
		PeerListItem:  item,
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
	var expiresAt *string
	if rec.ExpiresAt != nil {
		s := rec.ExpiresAt.UTC().Format(time.RFC3339)
		expiresAt = &s
	}
	allowedIPs := make([]string, len(rec.AllowedIPs))
	families := make([]string, 0, 2)
	for i := range rec.AllowedIPs {
		allowedIPs[i] = rec.AllowedIPs[i].String()
		if rec.AllowedIPs[i].IP.To4() != nil {
			families = appendIfNotPresent(families, FamilyIPv4)
		} else {
			families = appendIfNotPresent(families, FamilyIPv6)
		}
	}
	return PeerListItem{
		PeerID:          rec.PeerID,
		AllowedIPs:      allowedIPs,
		AddressFamilies: families,
		PublicKey:       rec.PublicKey.String(),
		Active:          active,
		LastHandshakeAt: lastHandshake,
		CreatedAt:       createdAt,
		ExpiresAt:       expiresAt,
	}
}

func appendIfNotPresent(slice []string, v string) []string {
	for _, x := range slice {
		if x == v {
			return slice
		}
	}
	return append(slice, v)
}

func (s *WireGuardService) rotatePeer(peerID string, record PeerRecord, expiresAt *time.Time) (PeerInfo, error) {
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
				AllowedIPs:                  record.AllowedIPs,
				ReplaceAllowedIPs:           true,
				PersistentKeepaliveInterval: keepaliveInterval(),
			},
		},
	}

	if err := s.client.ConfigureDevice(s.deviceName, config); err != nil {
		return PeerInfo{}, err
	}

	// Use new expiresAt if provided, otherwise keep existing
	effectiveExpiresAt := expiresAt
	if effectiveExpiresAt == nil {
		effectiveExpiresAt = record.ExpiresAt
	}
	s.store.Set(PeerRecord{
		PeerID:     peerID,
		PublicKey:  publicKey,
		AllowedIPs: record.AllowedIPs,
		CreatedAt:  record.CreatedAt,
		ExpiresAt:  effectiveExpiresAt,
	})

	allowedIPsStr := make([]string, len(record.AllowedIPs))
	peerFamilies := make([]string, 0, 2)
	for i := range record.AllowedIPs {
		allowedIPsStr[i] = record.AllowedIPs[i].String()
		if record.AllowedIPs[i].IP.To4() != nil {
			peerFamilies = appendIfNotPresent(peerFamilies, FamilyIPv4)
		} else {
			peerFamilies = appendIfNotPresent(peerFamilies, FamilyIPv6)
		}
	}
	return PeerInfo{
		PeerID:          peerID,
		PublicKey:       publicKey.String(),
		PrivateKey:      privateKey.String(),
		PresharedKey:    presharedKey.String(),
		AllowedIPs:      allowedIPsStr,
		AddressFamilies: peerFamilies,
	}, nil
}

// allocateIPs allocates one address per requested family. families must be validated (e.g. via ValidateAddressFamilies).
func (s *WireGuardService) allocateIPs(families []string) ([]net.IPNet, error) {
	used, err := s.collectUsedIPs()
	if err != nil {
		return nil, err
	}
	wantIPv4, wantIPv6 := familiesRequested(families)
	var out []net.IPNet
	if wantIPv4 && s.subnet4 != nil {
		ipNet, err := allocateOneIPv4(s.subnet4, used)
		if err != nil {
			return nil, err
		}
		out = append(out, ipNet)
	}
	if wantIPv6 && s.subnet6 != nil {
		ipNet, err := allocateOneIPv6(s.subnet6, used)
		if err != nil {
			return nil, err
		}
		out = append(out, ipNet)
	}
	return out, nil
}

func (s *WireGuardService) collectUsedIPs() (map[string]struct{}, error) {
	used := make(map[string]struct{})
	if s.serverIP4 != nil {
		used[s.serverIP4.String()] = struct{}{}
	}
	if s.serverIP6 != nil {
		used[s.serverIP6.String()] = struct{}{}
	}
	for _, record := range s.store.List() {
		for _, aip := range record.AllowedIPs {
			used[aip.IP.String()] = struct{}{}
		}
	}
	device, err := s.client.Device(s.deviceName)
	if err != nil {
		return nil, err
	}
	for _, peer := range device.Peers {
		for _, allowed := range peer.AllowedIPs {
			used[allowed.IP.String()] = struct{}{}
		}
	}
	return used, nil
}

func familiesRequested(families []string) (wantIPv4, wantIPv6 bool) {
	for _, f := range families {
		if f == FamilyIPv4 {
			wantIPv4 = true
		}
		if f == FamilyIPv6 {
			wantIPv6 = true
		}
	}
	return wantIPv4, wantIPv6
}

func allocateOneIPv4(subnet *net.IPNet, used map[string]struct{}) (net.IPNet, error) {
	start, end, err := ipv4Range(subnet)
	if err != nil {
		return net.IPNet{}, err
	}
	for ip := start; !ipAfter(ip, end); ip = nextIPv4(ip) {
		if _, exists := used[ip.String()]; exists {
			continue
		}
		used[ip.String()] = struct{}{}
		return net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
	}
	return net.IPNet{}, ErrNoAvailableIP
}

func allocateOneIPv6(subnet *net.IPNet, used map[string]struct{}) (net.IPNet, error) {
	start, end, err := ipv6Range(subnet)
	if err != nil {
		return net.IPNet{}, err
	}
	ones, _ := subnet.Mask.Size()
	maxIter := 0
	if ones < 112 {
		maxIter = maxIPv6PeersReported
	}
	n := 0
	for ip := start; !ipAfterIPv6(ip, end); ip = nextIPv6(ip) {
		if maxIter > 0 && n >= maxIter {
			break
		}
		n++
		if _, exists := used[ip.String()]; exists {
			continue
		}
		used[ip.String()] = struct{}{}
		return net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
	}
	return net.IPNet{}, ErrNoAvailableIP
}

func resolveServerIP4(subnet *net.IPNet, serverIP string) (net.IP, error) {
	if serverIP != "" {
		ip := net.ParseIP(serverIP)
		if ip == nil || ip.To4() == nil {
			return nil, errors.New("wireguard.server_ip must be a valid IPv4 address")
		}
		if !subnet.Contains(ip) {
			return nil, errors.New("wireguard.server_ip must be inside wireguard.subnet")
		}
		return ip.To4(), nil
	}
	start, _, err := ipv4Range(subnet)
	if err != nil {
		return nil, err
	}
	return start, nil
}

func resolveServerIP6(subnet *net.IPNet, serverIP string) (net.IP, error) {
	if serverIP != "" {
		ip := net.ParseIP(serverIP)
		if ip == nil || ip.To4() != nil {
			return nil, errors.New("wireguard.server_ip6 must be a valid IPv6 address")
		}
		if !subnet.Contains(ip) {
			return nil, errors.New("wireguard.server_ip6 must be inside wireguard.subnet6")
		}
		return ip, nil
	}
	start, _, err := ipv6Range(subnet)
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

func ipv6Range(subnet *net.IPNet) (net.IP, net.IP, error) {
	if subnet.IP.To4() != nil {
		return nil, nil, errors.New("expected IPv6 subnet")
	}
	ip := subnet.IP.To16()
	if ip == nil {
		return nil, nil, errors.New("invalid IPv6 subnet")
	}
	_, bits := subnet.Mask.Size()
	if bits != 128 {
		return nil, nil, errors.New("IPv6 mask must be 128 bits")
	}
	network := make(net.IP, 16)
	copy(network, ip)
	start := make(net.IP, 16)
	copy(start, network)
	for i := 15; i >= 0; i-- {
		if start[i] < 255 {
			start[i]++
			break
		}
		start[i] = 0
	}
	mask := subnet.Mask
	broadcast := make(net.IP, 16)
	for i := 0; i < 16; i++ {
		broadcast[i] = network[i] | ^mask[i]
	}
	end := make(net.IP, 16)
	copy(end, broadcast)
	for i := 15; i >= 0; i-- {
		if end[i] > 0 {
			end[i]--
			break
		}
		end[i] = 255
	}
	if ipAfterIPv6(start, end) {
		return nil, nil, errors.New("IPv6 subnet is too small")
	}
	return start, end, nil
}

func nextIPv6(ip net.IP) net.IP {
	next := make(net.IP, 16)
	copy(next, ip.To16())
	for i := 15; i >= 0; i-- {
		if next[i] < 255 {
			next[i]++
			return next
		}
		next[i] = 0
	}
	return next
}

func ipAfterIPv6(a, b net.IP) bool {
	a = a.To16()
	b = b.To16()
	for i := 0; i < 16; i++ {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
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

const maxIPv6PeersReported = 65536

func possiblePeerCountIPv6(subnet *net.IPNet, serverIP net.IP) (int, error) {
	start, end, err := ipv6Range(subnet)
	if err != nil {
		return 0, err
	}
	ones, _ := subnet.Mask.Size()
	if ones < 112 {
		// Subnet too large to iterate; report capped count
		count := maxIPv6PeersReported
		if serverIP != nil {
			ip := serverIP.To16()
			if ip != nil && !ipAfterIPv6(start, ip) && !ipAfterIPv6(ip, end) {
				count--
			}
		}
		return count, nil
	}
	n := 0
	for ip := start; !ipAfterIPv6(ip, end); ip = nextIPv6(ip) {
		if serverIP != nil && ip.Equal(serverIP) {
			continue
		}
		n++
		if n > maxIPv6PeersReported {
			return maxIPv6PeersReported, nil
		}
	}
	return n, nil
}

func (s *WireGuardService) possiblePeerCountTotal() (int, error) {
	var total int
	if s.subnet4 != nil {
		n, err := possiblePeerCount(s.subnet4, s.serverIP4)
		if err != nil {
			return 0, err
		}
		total += n
	}
	if s.subnet6 != nil {
		n, err := possiblePeerCountIPv6(s.subnet6, s.serverIP6)
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}
