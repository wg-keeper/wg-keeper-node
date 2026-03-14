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
	testAPIKey       = "test-api-key-secure-key-longer!!"
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
  api_key: "test-api-key-secure-key-longer!!"
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
	if cfg.APIKey != "test-api-key-secure-key-longer!!" {
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

func TestLoadConfigAPIKeyTooShort(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "too-short-key"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  listen_port: 51820
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error for api_key shorter than %d characters", minAPIKeyLength)
	}
}

func TestLoadConfigInvalidPort(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "invalid"
auth:
  api_key: "test-api-key-secure-key-longer!!"
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
  api_key: "test-api-key-secure-key-longer!!"
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
  api_key: "test-api-key-secure-key-longer!!"
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
  api_key: "test-api-key-secure-key-longer!!"
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
  api_key: "test-api-key-secure-key-longer!!"
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
  api_key: "test-api-key-secure-key-longer!!"
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
  api_key: "test-api-key-secure-key-longer!!"
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
  api_key: "test-api-key-secure-key-longer!!"
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
  api_key: "test-api-key-secure-key-longer!!"
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
  api_key: "test-api-key-secure-key-longer!!"
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
  api_key: "test-api-key-secure-key-longer!!"
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
  api_key: "test-api-key-secure-key-longer!!"
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

// ---------- Addr ----------

func TestConfigAddr(t *testing.T) {
	cfg := Config{Port: 8080}
	got := cfg.Addr()
	want := "0.0.0.0:8080"
	if got != want {
		t.Fatalf("Addr(): got %q, want %q", got, want)
	}
}

// ---------- LoadConfig error paths ----------

func TestLoadConfigFileNotFound(t *testing.T) {
	t.Setenv("NODE_CONFIG", "/tmp/wg-keeper-test-nonexistent-config.yaml")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestLoadConfigPathIsDirectory(t *testing.T) {
	t.Setenv("NODE_CONFIG", t.TempDir())
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error when config path is a directory")
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	path := writeConfigFile(t, "{broken yaml: [")
	t.Setenv("NODE_CONFIG", path)
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

// ---------- parseOneAllowedIP ----------

func TestParseOneAllowedIPIPv6Address(t *testing.T) {
	ipNet, err := parseOneAllowedIP("field", 0, "::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ipNet == nil {
		t.Fatal("expected non-nil IPNet")
	}
	ones, bits := ipNet.Mask.Size()
	if ones != 128 || bits != 128 {
		t.Fatalf("expected /128 mask, got /%d", ones)
	}
}

func TestParseOneAllowedIPInvalidCIDR(t *testing.T) {
	_, err := parseOneAllowedIP("field", 0, "10.0.0.0/33")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

// ---------- validateWireGuardSubnet helpers ----------

func TestValidateWireGuardSubnet4RejectsIPv6(t *testing.T) {
	if err := validateWireGuardSubnet4("fd00::/64"); err == nil {
		t.Fatal("expected error for IPv6 CIDR in validateWireGuardSubnet4")
	}
}

func TestValidateWireGuardSubnet4PrefixTooLong(t *testing.T) {
	if err := validateWireGuardSubnet4("10.0.0.0/31"); err == nil {
		t.Fatal("expected error for /31 IPv4 subnet in validateWireGuardSubnet4")
	}
	if err := validateWireGuardSubnet4("10.0.0.0/30"); err != nil {
		t.Fatalf("expected /30 IPv4 to be valid in validateWireGuardSubnet4, got %v", err)
	}
}

func TestValidateWireGuardSubnet6RejectsIPv4(t *testing.T) {
	if err := validateWireGuardSubnet6("10.0.0.0/24"); err == nil {
		t.Fatal("expected error for IPv4 CIDR in validateWireGuardSubnet6")
	}
}

func TestLoadConfigNodeConfigWhitespace(t *testing.T) {
	// Whitespace-only NODE_CONFIG trims to "" → defaults to "config.yaml" which shouldn't exist in test dir.
	t.Setenv("NODE_CONFIG", "   ")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error when NODE_CONFIG is whitespace and config.yaml does not exist")
	}
}

func TestParseAllowedIPsAllEmptyStrings(t *testing.T) {
	nets, err := parseAllowedIPs("field", []string{"", " ", ""})
	if err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
	if nets != nil {
		t.Fatalf("expected nil nets for all-empty entries, got %v", nets)
	}
}

func TestParseAllowedIPsIPv6CIDR(t *testing.T) {
	nets, err := parseAllowedIPs("field", []string{"fd00::/64"})
	if err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
	if len(nets) != 1 {
		t.Fatalf("expected 1 net, got %d", len(nets))
	}
}

func TestOptionalIPv4WithIPv6Address(t *testing.T) {
	_, err := optionalIPv4("field", "fd00::1")
	if err == nil {
		t.Fatal("expected error for IPv6 address in optionalIPv4")
	}
}

func TestOptionalIPv6WithIPv4Address(t *testing.T) {
	_, err := optionalIPv6("field", "10.0.0.1")
	if err == nil {
		t.Fatal("expected error for IPv4 address in optionalIPv6")
	}
}

func TestParsePortZero(t *testing.T) {
	if _, err := parsePort("field", "0"); err == nil {
		t.Fatal("expected error for port 0")
	}
}

func TestParsePortMaxValid(t *testing.T) {
	port, err := parsePort("field", "65535")
	if err != nil || port != 65535 {
		t.Fatalf("expected port 65535, got %d, err: %v", port, err)
	}
}

func TestParsePortTooHigh(t *testing.T) {
	if _, err := parsePort("field", "65536"); err == nil {
		t.Fatal("expected error for port 65536")
	}
}

func TestRequirePortZero(t *testing.T) {
	if err := requirePort("field", 0); err == nil {
		t.Fatal("expected error for port 0")
	}
}

func TestRequirePortValid(t *testing.T) {
	if err := requirePort("field", 51820); err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
}

func TestTLSEnabledFalse(t *testing.T) {
	cfg := Config{}
	if cfg.TLSEnabled() {
		t.Error("expected TLSEnabled=false when no cert/key configured")
	}
}

func TestTLSEnabledTrue(t *testing.T) {
	cfg := Config{TLSCertFile: "cert.pem", TLSKeyFile: "key.pem"}
	if !cfg.TLSEnabled() {
		t.Error("expected TLSEnabled=true when both cert and key are set")
	}
}

func TestLoadConfigInvalidServerIP6(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "test-api-key-secure-key-longer!!"
wireguard:
  interface: "wg0"
  subnet6: "fd00::/112"
  server_ip6: "10.0.0.1"
  listen_port: 51820
  routing:
    wan_interface: "eth0"
`)
	t.Setenv("NODE_CONFIG", path)
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error for IPv4 address as server_ip6")
	}
}

func TestValidateWireGuardSubnet6PrefixTooLong(t *testing.T) {
	if err := validateWireGuardSubnet6("fd00::/127"); err == nil {
		t.Fatal("expected error for /127 IPv6 subnet in validateWireGuardSubnet6")
	}
	if err := validateWireGuardSubnet6("fd00::/126"); err != nil {
		t.Fatalf("expected /126 IPv6 to be valid in validateWireGuardSubnet6, got %v", err)
	}
}
