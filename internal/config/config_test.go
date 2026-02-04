package config

import (
	"os"
	"path/filepath"
	"testing"
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
		t.Fatalf("expected no error, got %v", err)
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
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error for invalid subnet")
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
		t.Fatalf("expected no error, got %v", err)
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
