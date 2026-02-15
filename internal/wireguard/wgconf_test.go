package wireguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wg-keeper/wg-keeper-node/internal/config"
)

const (
	wgconfTestAddressLine = "10.0.0.1/24"
)

func TestBuildConfigContent(t *testing.T) {
	cfg := config.Config{}
	content := buildConfigContent("privkey123", []string{wgconfTestAddressLine}, 51820, cfg)
	if !strings.Contains(content, "[Interface]") {
		t.Error("expected [Interface] in content")
	}
	if !strings.Contains(content, "PrivateKey = privkey123") {
		t.Error("expected PrivateKey in content")
	}
	if !strings.Contains(content, "Address = "+wgconfTestAddressLine) {
		t.Error("expected Address in content")
	}
	if !strings.Contains(content, "ListenPort = 51820") {
		t.Error("expected ListenPort in content")
	}
}

func TestBuildConfigContentWithPostUp(t *testing.T) {
	cfg := config.Config{
		WANInterface: "eth0",
		WGSubnet:     subnetTestCIDR,
	}
	content := buildConfigContent("pk", []string{wgconfTestAddressLine}, 51820, cfg)
	if !strings.Contains(content, "PostUp = ") {
		t.Error("expected PostUp when WANInterface and WGSubnet set")
	}
	if !strings.Contains(content, "PostDown = ") {
		t.Error("expected PostDown when WANInterface and WGSubnet set")
	}
	if !strings.Contains(content, "iptables") {
		t.Error("expected iptables in routing rules")
	}
}

func TestBuildRoutingRules(t *testing.T) {
	t.Run("empty_wan_returns_nil", func(t *testing.T) {
		up, down := buildRoutingRules(config.Config{})
		if up != nil || down != nil {
			t.Errorf("expected nil, got up=%v down=%v", up, down)
		}
	})

	t.Run("wan_only_no_subnet_returns_nil", func(t *testing.T) {
		up, down := buildRoutingRules(config.Config{WANInterface: "eth0"})
		if up != nil || down != nil {
			t.Errorf("expected nil without subnet, got up=%v down=%v", up, down)
		}
	})

	t.Run("wan_and_subnet4_returns_rules", func(t *testing.T) {
		cfg := config.Config{WANInterface: "eth0", WGSubnet: subnetTestCIDR}
		up, down := buildRoutingRules(cfg)
		if len(up) == 0 || len(down) == 0 {
			t.Errorf("expected rules, got up=%v down=%v", up, down)
		}
		if len(up) != 3 || len(down) != 3 {
			t.Errorf("expected 3 up and 3 down, got %d up %d down", len(up), len(down))
		}
	})

	t.Run("wan_and_subnet6_returns_ip6tables_rules", func(t *testing.T) {
		cfg := config.Config{WANInterface: "eth0", WGSubnet6: subnet6TestCIDR64}
		up, down := buildRoutingRules(cfg)
		if len(up) == 0 || len(down) == 0 {
			t.Errorf("expected rules, got up=%v down=%v", up, down)
		}
		joined := strings.Join(up, " ")
		if !strings.Contains(joined, "ip6tables") {
			t.Error("expected ip6tables in rules")
		}
	})
}

func TestAddressLineFromSubnet4(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		addr, err := addressLineFromSubnet4(subnetTestCIDR, ipServerTest)
		if err != nil {
			t.Fatalf(msgUnexpectedError, err)
		}
		if addr != wgconfTestAddressLine {
			t.Errorf("got %q", addr)
		}
	})

	t.Run("invalid_subnet", func(t *testing.T) {
		_, err := addressLineFromSubnet4("invalid", "")
		if err == nil {
			t.Error("expected error for invalid subnet")
		}
	})

	t.Run("ipv6_subnet_returns_error", func(t *testing.T) {
		_, err := addressLineFromSubnet4(subnet6TestCIDR64, "")
		if err == nil {
			t.Error("expected error for IPv6 subnet")
		}
	})
}

func TestAddressLineFromSubnet6(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		addr, err := addressLineFromSubnet6(subnet6TestCIDR64, ipv6TestAddr1)
		if err != nil {
			t.Fatalf(msgUnexpectedError, err)
		}
		if !strings.HasPrefix(addr, "fd00::") || !strings.HasSuffix(addr, "/64") {
			t.Errorf("got %q", addr)
		}
	})

	t.Run("ipv4_subnet_returns_error", func(t *testing.T) {
		_, err := addressLineFromSubnet6(subnetTestCIDR, "")
		if err == nil {
			t.Error("expected error for IPv4 subnet")
		}
	})
}

func TestBuildAddressLines(t *testing.T) {
	t.Run("empty_config", func(t *testing.T) {
		lines, err := buildAddressLines(config.Config{})
		if err != nil {
			t.Fatalf(msgUnexpectedError, err)
		}
		if len(lines) != 0 {
			t.Errorf("expected no lines, got %v", lines)
		}
	})

	t.Run("subnet4_only", func(t *testing.T) {
		lines, err := buildAddressLines(config.Config{WGSubnet: subnetTestCIDR, WGServerIP: ipServerTest})
		if err != nil {
			t.Fatalf(msgUnexpectedError, err)
		}
		if len(lines) != 1 || !strings.HasPrefix(lines[0], "10.0.0.1") {
			t.Errorf("expected one IPv4 line, got %v", lines)
		}
	})
}

func TestCheckExistingConfig(t *testing.T) {
	dir := t.TempDir()

	t.Run("not_exists", func(t *testing.T) {
		path := filepath.Join(dir, "nonexistent")
		exists, err := checkExistingConfig(path)
		if err != nil {
			t.Fatalf(msgUnexpectedError, err)
		}
		if exists {
			t.Error("expected false for missing file")
		}
	})

	t.Run("exists_as_file", func(t *testing.T) {
		path := filepath.Join(dir, "exists.conf")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}
		exists, err := checkExistingConfig(path)
		if err != nil {
			t.Fatalf(msgUnexpectedError, err)
		}
		if !exists {
			t.Error("expected true for existing file")
		}
	})

	t.Run("path_is_directory", func(t *testing.T) {
		path := filepath.Join(dir, "subdir")
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		exists, err := checkExistingConfig(path)
		if err == nil {
			t.Error("expected error when path is directory")
		}
		if exists {
			t.Error("expected false when path is directory")
		}
	})
}

func TestDefaultConfigPath(t *testing.T) {
	path := defaultConfigPath("")
	if !strings.Contains(path, "wg0") {
		t.Errorf("empty iface should default to wg0, got %q", path)
	}
	path = defaultConfigPath("wg1")
	if !strings.Contains(path, "wg1") {
		t.Errorf("expected wg1 in path, got %q", path)
	}
}
