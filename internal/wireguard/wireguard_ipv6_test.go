package wireguard

import (
	"net"
	"testing"
)

const (
	subnet6TestCIDR   = "fd00::/120"
	subnet6TestCIDR64 = "fd00::/64"
	ipv6TestAddr1     = "fd00::1"
)

func TestIPv6Range(t *testing.T) {
	_, subnet, _ := net.ParseCIDR(subnet6TestCIDR)
	start, end, err := ipv6Range(subnet)
	if err != nil {
		t.Fatalf("ipv6Range: %v", err)
	}
	if start == nil || end == nil {
		t.Fatal("start and end should be non-nil")
	}
	if ipAfterIPv6(start, end) {
		t.Error("start should be before or equal to end")
	}
}

func TestIPv6RangeInvalidSubnet(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR("10.0.0.0/24")
	_, _, err := ipv6Range(subnet4)
	if err == nil {
		t.Error("expected error for IPv4 subnet")
	}
}

func TestIPv6RangeTooSmall(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("fd00::/128")
	_, _, err := ipv6Range(subnet)
	if err == nil {
		t.Error("expected error for /128 subnet")
	}
}

func TestNextIPv6(t *testing.T) {
	ip := net.ParseIP(ipv6TestAddr1)
	next := nextIPv6(ip)
	if next == nil {
		t.Fatal("next should be non-nil")
	}
	if next.String() != "fd00::2" {
		t.Errorf("expected fd00::2, got %s", next.String())
	}
}

func TestNextIPv6Rollover(t *testing.T) {
	ip := net.ParseIP("fd00::ff")
	next := nextIPv6(ip)
	if next.String() != "fd00::100" {
		t.Errorf("expected fd00::100, got %s", next.String())
	}
}

func TestIPAfterIPv6(t *testing.T) {
	a := net.ParseIP("fd00::2")
	b := net.ParseIP(ipv6TestAddr1)
	if !ipAfterIPv6(a, b) {
		t.Error("a should be after b")
	}
	if ipAfterIPv6(b, a) {
		t.Error("b should not be after a")
	}
	if ipAfterIPv6(a, a) {
		t.Error("same IP should not be after itself")
	}
}

func TestResolveServerIP6(t *testing.T) {
	_, subnet, _ := net.ParseCIDR(subnet6TestCIDR64)
	ip, err := resolveServerIP6(subnet, ipv6TestAddr1)
	if err != nil {
		t.Fatalf("resolveServerIP6: %v", err)
	}
	if ip.String() != ipv6TestAddr1 {
		t.Errorf("got %s", ip.String())
	}

	_, err = resolveServerIP6(subnet, "not-an-ip") // invalid
	if err == nil {
		t.Error("expected error for invalid IP")
	}

	_, err = resolveServerIP6(subnet, "10.0.0.1") // IPv4
	if err == nil {
		t.Error("expected error for IPv4")
	}

	_, err = resolveServerIP6(subnet, "fd01::1") // outside subnet
	if err == nil {
		t.Error("expected error for IP outside subnet")
	}
}

func TestResolveServerIP6EmptyUsesFirst(t *testing.T) {
	_, subnet, _ := net.ParseCIDR(subnet6TestCIDR)
	ip, err := resolveServerIP6(subnet, "")
	if err != nil {
		t.Fatalf("resolveServerIP6: %v", err)
	}
	if ip == nil {
		t.Fatal("expected non-nil IP")
	}
}

func TestAllocateOneIPv6(t *testing.T) {
	_, subnet, _ := net.ParseCIDR(subnet6TestCIDR)
	used := map[string]struct{}{}
	ipNet, err := allocateOneIPv6(subnet, used)
	if err != nil {
		t.Fatalf("allocateOneIPv6: %v", err)
	}
	if ipNet.IP.String() != ipv6TestAddr1 {
		t.Errorf("expected %s, got %s", ipv6TestAddr1, ipNet.IP.String())
	}
	if _, ok := used[ipNet.IP.String()]; !ok {
		t.Error("used should contain allocated IP")
	}
}

func TestPossiblePeerCountIPv6(t *testing.T) {
	_, subnet, _ := net.ParseCIDR(subnet6TestCIDR)
	n, err := possiblePeerCountIPv6(subnet, nil)
	if err != nil {
		t.Fatalf("possiblePeerCountIPv6: %v", err)
	}
	if n <= 0 {
		t.Errorf("expected positive count, got %d", n)
	}
}

func TestAppendIfNotPresent(t *testing.T) {
	slice := []string{"a", "b"}
	got := appendIfNotPresent(slice, "c")
	if len(got) != 3 || got[2] != "c" {
		t.Errorf("expected [a b c], got %v", got)
	}
	got = appendIfNotPresent(slice, "a")
	if len(got) != 2 {
		t.Errorf("should not duplicate a, got %v", got)
	}
}
