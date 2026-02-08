package config

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

const msgExpectedNoError = "expected no error, got %v"

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
  port: "51821"
auth:
  api_key: "test-key"
wireguard:
  interface: "wg0"
  subnet6: "fd00::/112"
  server_ip6: "fd00::1"
  listen_port: 51820
  routing:
    wan_interface: "eth0"
`)
	t.Setenv("NODE_CONFIG", path)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
	if cfg.WGSubnet != "" {
		t.Fatalf("expected no IPv4 subnet, got %q", cfg.WGSubnet)
	}
	if cfg.WGSubnet6 != "fd00::/112" {
		t.Fatalf("expected subnet6 fd00::/112, got %q", cfg.WGSubnet6)
	}
	if cfg.WGServerIP6 != "fd00::1" {
		t.Fatalf("expected server_ip6 fd00::1, got %q", cfg.WGServerIP6)
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
  port: "51821"
  allowed_ips:
    - "10.0.0.0/24"
    - "192.168.1.1"
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
	if cfg.AllowedNets == nil || len(cfg.AllowedNets) != 2 {
		t.Fatalf("expected 2 allowed nets, got %v", cfg.AllowedNets)
	}
	// 10.0.0.0/24
	if !cfg.AllowedNets[0].Contains(net.ParseIP("10.0.0.1")) {
		t.Fatal("expected first net to contain 10.0.0.1")
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
