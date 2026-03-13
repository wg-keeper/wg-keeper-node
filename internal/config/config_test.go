package config

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

const msgExpectedNoError = "expected no error, got %v"

const (
	testPort         = "51821"
	testAPIKey       = "test-key"
	testWGSubnet4    = "10.0.0.0/24"
	testWGServerIP4  = "10.0.0.1"
	testWGSubnet6    = "fd00::/112"
	testWGServerIP6  = "fd00::1"
	testWANInterface = "eth0"
)

func writeConfigFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadConfigValid(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "test-key"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  server_ip: "10.0.0.1"
  listen_port: 51820
  routing:
    wan_interface: "eth0"
`)
	t.Setenv("NODE_CONFIG", path)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
	if cfg.Port != 51821 {
		t.Fatalf("expected port 51821, got %d", cfg.Port)
	}
	if cfg.APIKey != "test-key" {
		t.Fatalf("unexpected api key: %q", cfg.APIKey)
	}
	if cfg.WGInterface != "wg0" {
		t.Fatalf("unexpected interface: %q", cfg.WGInterface)
	}
	if cfg.WGListenPort != 51820 {
		t.Fatalf("unexpected listen port: %d", cfg.WGListenPort)
	}
}

func TestLoadConfigMissingAPIKey(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: ""
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  listen_port: 51820
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error for missing api_key")
	}
}

func TestLoadConfigInvalidPort(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "invalid"
auth:
  api_key: "test-key"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  listen_port: 51820
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error for invalid port")
	}
}

func TestLoadConfigInvalidSubnet(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "test-key"
wireguard:
  interface: "wg0"
  subnet: "not-a-cidr"
  listen_port: 51820
  routing:
    wan_interface: "eth0"
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error for invalid subnet")
	}
}

func TestLoadConfigNoSubnet(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "test-key"
wireguard:
  interface: "wg0"
  listen_port: 51820
  routing:
    wan_interface: "eth0"
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error when neither subnet nor subnet6 is set")
	}
}

func TestLoadConfigIPv6Only(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "`+testPort+`"
auth:
  api_key: "`+testAPIKey+`"
wireguard:
  interface: "wg0"
  subnet6: "`+testWGSubnet6+`"
  server_ip6: "`+testWGServerIP6+`"
  listen_port: 51820
  routing:
    wan_interface: "`+testWANInterface+`"
`)
	t.Setenv("NODE_CONFIG", path)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
	if cfg.WGSubnet != "" {
		t.Fatalf("expected no IPv4 subnet, got %q", cfg.WGSubnet)
	}
	if cfg.WGSubnet6 != testWGSubnet6 {
		t.Fatalf("expected subnet6 %s, got %q", testWGSubnet6, cfg.WGSubnet6)
	}
	if cfg.WGServerIP6 != testWGServerIP6 {
		t.Fatalf("expected server_ip6 %s, got %q", testWGServerIP6, cfg.WGServerIP6)
	}
}

func TestLoadConfigInvalidListenPort(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "test-key"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  listen_port: 70000
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error for invalid listen port")
	}
}

func TestLoadConfigInvalidServerIP(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "test-key"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  server_ip: "not-an-ip"
  listen_port: 51820
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error for invalid server_ip")
	}
}

func TestLoadConfigMissingInterface(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "test-key"
wireguard:
  interface: ""
  subnet: "10.0.0.0/24"
  listen_port: 51820
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error for missing interface")
	}
}

func TestLoadConfigTLSEnabled(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
  tls_cert: "/etc/certs/server.pem"
  tls_key: "/etc/certs/server-key.pem"
auth:
  api_key: "test-key"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  server_ip: "10.0.0.1"
  listen_port: 51820
  routing:
    wan_interface: "eth0"
`)
	t.Setenv("NODE_CONFIG", path)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
	if !cfg.TLSEnabled() {
		t.Fatalf("expected TLS enabled")
	}
	if cfg.TLSCertFile != "/etc/certs/server.pem" || cfg.TLSKeyFile != "/etc/certs/server-key.pem" {
		t.Fatalf("unexpected TLS paths: cert=%q key=%q", cfg.TLSCertFile, cfg.TLSKeyFile)
	}
}

func TestLoadConfigTLSOnlyCert(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
  tls_cert: "/etc/certs/server.pem"
auth:
  api_key: "test-key"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  listen_port: 51820
  routing:
    wan_interface: "eth0"
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error when only tls_cert is set")
	}
}

func TestLoadConfigTLSOnlyKey(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
  tls_key: "/etc/certs/server-key.pem"
auth:
  api_key: "test-key"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  listen_port: 51820
  routing:
    wan_interface: "eth0"
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error when only tls_key is set")
	}
}

func TestLoadConfigAllowedIPs(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "`+testPort+`"
  allowed_ips:
    - "`+testWGSubnet4+`"
    - "192.168.1.1"
auth:
  api_key: "`+testAPIKey+`"
wireguard:
  interface: "wg0"
  subnet: "`+testWGSubnet4+`"
  server_ip: "`+testWGServerIP4+`"
  listen_port: 51820
  routing:
    wan_interface: "`+testWANInterface+`"
`)
	t.Setenv("NODE_CONFIG", path)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
	if cfg.AllowedNets == nil || len(cfg.AllowedNets) != 2 {
		t.Fatalf("expected 2 allowed nets, got %v", cfg.AllowedNets)
	}
	// testWGSubnet4
	if !cfg.AllowedNets[0].Contains(net.ParseIP(testWGServerIP4)) {
		t.Fatalf("expected first net to contain %s", testWGServerIP4)
	}
	// 192.168.1.1/32
	if !cfg.AllowedNets[1].Contains(net.ParseIP("192.168.1.1")) {
		t.Fatal("expected second net to contain 192.168.1.1")
	}
	if cfg.AllowedNets[1].Contains(net.ParseIP("192.168.1.2")) {
		t.Fatal("expected /32 to not contain 192.168.1.2")
	}
}

func TestLoadConfigAllowedIPsInvalid(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
  allowed_ips:
    - "10.0.0.0/24"
    - "not-an-ip"
auth:
  api_key: "test-key"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  server_ip: "10.0.0.1"
  listen_port: 51820
  routing:
    wan_interface: "eth0"
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error for invalid allowed_ips entry")
	}
}

func TestLoadConfigPeerStoreFile(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "test-key"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  server_ip: "10.0.0.1"
  listen_port: 51820
  peer_store_file: "peers.json"
  routing:
    wan_interface: "eth0"
`)
	t.Setenv("NODE_CONFIG", path)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
	if cfg.PeerStoreFile != "peers.json" {
		t.Fatalf("expected peer_store_file peers.json, got %q", cfg.PeerStoreFile)
	}
}

// ---------- subnet size validation ----------

const subnetValidationBase = `
server:
  port: "51821"
auth:
  api_key: "test-key"
wireguard:
  interface: "wg0"
  listen_port: 51820
  routing:
    wan_interface: "eth0"
`

func writeSubnetConfig(t *testing.T, subnet, subnet6 string) string {
	t.Helper()
	content := subnetValidationBase
	if subnet != "" {
		content += "  subnet: " + `"` + subnet + `"` + "\n"
	}
	if subnet6 != "" {
		content += "  subnet6: " + `"` + subnet6 + `"` + "\n"
	}
	return writeConfigFile(t, content)
}

func TestLoadConfigSubnet32Rejected(t *testing.T) {
	path := writeSubnetConfig(t, "10.0.0.1/32", "")
	t.Setenv("NODE_CONFIG", path)
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error for /32 IPv4 subnet (too small)")
	}
}

func TestLoadConfigSubnet31Rejected(t *testing.T) {
	path := writeSubnetConfig(t, "10.0.0.0/31", "")
	t.Setenv("NODE_CONFIG", path)
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error for /31 IPv4 subnet (too small)")
	}
}

func TestLoadConfigSubnet30Valid(t *testing.T) {
	path := writeSubnetConfig(t, "10.0.0.0/30", "")
	t.Setenv("NODE_CONFIG", path)
	if _, err := LoadConfig(); err != nil {
		t.Fatalf("expected /30 IPv4 to be valid, got error: %v", err)
	}
}

func TestLoadConfigSubnet128IPv6Rejected(t *testing.T) {
	path := writeSubnetConfig(t, "", "fd00::1/128")
	t.Setenv("NODE_CONFIG", path)
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error for /128 IPv6 subnet (too small)")
	}
}

func TestLoadConfigSubnet127IPv6Rejected(t *testing.T) {
	path := writeSubnetConfig(t, "", "fd00::/127")
	t.Setenv("NODE_CONFIG", path)
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error for /127 IPv6 subnet (too small)")
	}
}

func TestLoadConfigSubnet126IPv6Valid(t *testing.T) {
	path := writeSubnetConfig(t, "", "fd00::/126")
	t.Setenv("NODE_CONFIG", path)
	if _, err := LoadConfig(); err != nil {
		t.Fatalf("expected /126 IPv6 to be valid, got error: %v", err)
	}
}
