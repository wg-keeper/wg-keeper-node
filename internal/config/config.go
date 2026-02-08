package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
)

const errMsgRequired = "%s is required"

type Config struct {
	Port         int
	APIKey       string
	TLSCertFile  string // path to TLS certificate (PEM); if set, TLSKeyFile must be set too
	TLSKeyFile   string // path to TLS private key (PEM)
	AllowedNets  []*net.IPNet // optional: if non-empty, only these IPs/CIDRs may reach the API
	WGInterface  string
	WGSubnet     string   // IPv4 CIDR (optional if WGSubnet6 is set)
	WGServerIP   string   // IPv4 server address (optional)
	WGSubnet6    string   // IPv6 CIDR (optional if WGSubnet is set)
	WGServerIP6  string   // IPv6 server address (optional)
	WGListenPort int
	WANInterface string
}

type wireguardRouting struct {
	WANInterface string `yaml:"wan_interface"`
}

type fileConfig struct {
	Server struct {
		Port       string   `yaml:"port"`
		TLSCert    string   `yaml:"tls_cert"`
		TLSKey     string   `yaml:"tls_key"`
		AllowedIPs []string  `yaml:"allowed_ips"`
	} `yaml:"server"`
	Auth struct {
		APIKey string `yaml:"api_key"`
	} `yaml:"auth"`
	WireGuard struct {
		Interface  string           `yaml:"interface"`
		Subnet     string           `yaml:"subnet"`
		ServerIP   string           `yaml:"server_ip"`
		Subnet6    string           `yaml:"subnet6"`
		ServerIP6  string           `yaml:"server_ip6"`
		ListenPort int              `yaml:"listen_port"`
		Routing    wireguardRouting `yaml:"routing"`
	} `yaml:"wireguard"`
}

func LoadConfig() (Config, error) {
	configPath := strings.TrimSpace(os.Getenv("NODE_CONFIG"))
	if configPath == "" {
		configPath = "config.yaml"
	}

	info, err := os.Stat(configPath)
	if err == nil {
		if info.IsDir() {
			return Config{}, fmt.Errorf("config path is a directory: %s", configPath)
		}
		return loadConfigFile(configPath)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Config{}, fmt.Errorf("stat config: %w", err)
	}
	return Config{}, fmt.Errorf("config file not found: %s", configPath)
}

func loadConfigFile(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var fc fileConfig
	if err := yaml.Unmarshal(raw, &fc); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	portValue, apiKey, tlsCert, tlsKey, allowedNets, err := parseServerAndAuth(fc)
	if err != nil {
		return Config{}, err
	}
	wgSubnet, wgSubnet6, wgInterface, wgServerIP, wgServerIP6, wanInterface, wgListenPort, err := parseWireGuard(fc)
	if err != nil {
		return Config{}, err
	}
	return Config{
		Port:         portValue,
		APIKey:       apiKey,
		TLSCertFile:  tlsCert,
		TLSKeyFile:   tlsKey,
		AllowedNets:  allowedNets,
		WGInterface:  wgInterface,
		WGSubnet:     wgSubnet,
		WGServerIP:   wgServerIP,
		WGSubnet6:    wgSubnet6,
		WGServerIP6:  wgServerIP6,
		WGListenPort: wgListenPort,
		WANInterface: wanInterface,
	}, nil
}

func parseServerAndAuth(fc fileConfig) (portValue int, apiKey, tlsCert, tlsKey string, allowedNets []*net.IPNet, err error) {
	portValue, err = parsePort("server.port", fc.Server.Port)
	if err != nil {
		return 0, "", "", "", nil, err
	}
	apiKey, err = requireString("auth.api_key", fc.Auth.APIKey)
	if err != nil {
		return 0, "", "", "", nil, err
	}
	tlsCert, tlsKey, err = parseOptionalTLS(fc.Server.TLSCert, fc.Server.TLSKey)
	if err != nil {
		return 0, "", "", "", nil, err
	}
	allowedNets, err = parseAllowedIPs("server.allowed_ips", fc.Server.AllowedIPs)
	if err != nil {
		return 0, "", "", "", nil, err
	}
	return portValue, apiKey, tlsCert, tlsKey, allowedNets, nil
}

func parseWireGuard(fc fileConfig) (wgSubnet, wgSubnet6, wgInterface, wgServerIP, wgServerIP6, wanInterface string, wgListenPort int, err error) {
	wgSubnet, err = optionalCIDR("wireguard.subnet", fc.WireGuard.Subnet)
	if err != nil {
		return "", "", "", "", "", "", 0, err
	}
	wgSubnet6, err = optionalCIDR("wireguard.subnet6", fc.WireGuard.Subnet6)
	if err != nil {
		return "", "", "", "", "", "", 0, err
	}
	if err := validateWireGuardSubnets(wgSubnet, wgSubnet6); err != nil {
		return "", "", "", "", "", "", 0, err
	}
	wgInterface, err = requireString("wireguard.interface", fc.WireGuard.Interface)
	if err != nil {
		return "", "", "", "", "", "", 0, err
	}
	wgListenPort = fc.WireGuard.ListenPort
	if err := requirePort("wireguard.listen_port", wgListenPort); err != nil {
		return "", "", "", "", "", "", 0, err
	}
	wgServerIP, err = optionalIPv4("wireguard.server_ip", fc.WireGuard.ServerIP)
	if err != nil {
		return "", "", "", "", "", "", 0, err
	}
	wgServerIP6, err = optionalIPv6("wireguard.server_ip6", fc.WireGuard.ServerIP6)
	if err != nil {
		return "", "", "", "", "", "", 0, err
	}
	wanInterface, err = requireString("wireguard.routing.wan_interface", fc.WireGuard.Routing.WANInterface)
	if err != nil {
		return "", "", "", "", "", "", 0, err
	}
	return wgSubnet, wgSubnet6, wgInterface, wgServerIP, wgServerIP6, wanInterface, wgListenPort, nil
}

func validateWireGuardSubnets(wgSubnet, wgSubnet6 string) error {
	if wgSubnet == "" && wgSubnet6 == "" {
		return fmt.Errorf("at least one of wireguard.subnet or wireguard.subnet6 is required")
	}
	if wgSubnet != "" {
		_, ipNet, _ := net.ParseCIDR(wgSubnet)
		if ipNet != nil && ipNet.IP.To4() == nil {
			return fmt.Errorf("wireguard.subnet must be an IPv4 CIDR")
		}
	}
	if wgSubnet6 != "" {
		_, ipNet, _ := net.ParseCIDR(wgSubnet6)
		if ipNet != nil && ipNet.IP.To4() != nil {
			return fmt.Errorf("wireguard.subnet6 must be an IPv6 CIDR")
		}
	}
	return nil
}

// TLSEnabled reports whether TLS (HTTPS) is configured (both cert and key are set).
func (c Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// parseOptionalTLS returns cert and key paths. Both must be set or both unset; otherwise returns error.
func parseOptionalTLS(cert, key string) (certPath, keyPath string, err error) {
	certPath = strings.TrimSpace(cert)
	keyPath = strings.TrimSpace(key)
	if certPath == "" && keyPath == "" {
		return "", "", nil
	}
	if certPath == "" {
		return "", "", fmt.Errorf("server.tls_key is set but server.tls_cert is missing; set both for HTTPS")
	}
	if keyPath == "" {
		return "", "", fmt.Errorf("server.tls_cert is set but server.tls_key is missing; set both for HTTPS")
	}
	return certPath, keyPath, nil
}

func (c Config) Addr() string {
	return fmt.Sprintf("0.0.0.0:%d", c.Port)
}

func requireString(field, value string) (string, error) {
	out := strings.TrimSpace(value)
	if out == "" {
		return "", fmt.Errorf(errMsgRequired, field)
	}
	return out, nil
}

func parsePort(field, value string) (int, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return 0, fmt.Errorf(errMsgRequired, field)
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("%s must be a valid TCP port", field)
	}
	return port, nil
}

func requirePort(field string, port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("%s must be a valid UDP port", field)
	}
	return nil
}

func optionalCIDR(field, value string) (string, error) {
	out := strings.TrimSpace(value)
	if out == "" {
		return "", nil
	}
	if _, _, err := net.ParseCIDR(out); err != nil {
		return "", fmt.Errorf("%s must be a valid CIDR", field)
	}
	return out, nil
}

func optionalIPv4(field, value string) (string, error) {
	out := strings.TrimSpace(value)
	if out == "" {
		return "", nil
	}
	parsed := net.ParseIP(out)
	if parsed == nil || parsed.To4() == nil {
		return "", fmt.Errorf("%s must be a valid IPv4 address", field)
	}
	return out, nil
}

func optionalIPv6(field, value string) (string, error) {
	out := strings.TrimSpace(value)
	if out == "" {
		return "", nil
	}
	parsed := net.ParseIP(out)
	if parsed == nil || parsed.To4() != nil {
		return "", fmt.Errorf("%s must be a valid IPv6 address", field)
	}
	return out, nil
}

// parseAllowedIPs parses a list of IPv4 or IPv6 addresses or CIDRs.
// Returns nil when the list is empty or nil (no whitelist). Each entry is normalized to *net.IPNet.
func parseAllowedIPs(field string, entries []string) ([]*net.IPNet, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	nets := make([]*net.IPNet, 0, len(entries))
	for i, s := range entries {
		ipNet, err := parseOneAllowedIP(field, i, strings.TrimSpace(s))
		if err != nil {
			return nil, err
		}
		if ipNet != nil {
			nets = append(nets, ipNet)
		}
	}
	if len(nets) == 0 {
		return nil, nil
	}
	return nets, nil
}

// parseOneAllowedIP parses a single IPv4/IPv6 or CIDR entry. Returns (nil, nil) for empty s (skip).
func parseOneAllowedIP(field string, index int, s string) (*net.IPNet, error) {
	if s == "" {
		return nil, nil
	}
	if strings.Contains(s, "/") {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: invalid CIDR %q: %w", field, index, s, err)
		}
		return ipNet, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("%s[%d]: invalid IP address %q", field, index, s)
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}
