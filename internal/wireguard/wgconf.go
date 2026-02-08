package wireguard

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/wg-keeper/wg-keeper-node/internal/config"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func EnsureWireGuardConfig(cfg config.Config) (string, error) {
	confPath := defaultConfigPath(cfg.WGInterface)
	useExisting, err := checkExistingConfig(confPath)
	if err != nil {
		return "", err
	}
	if useExisting {
		return confPath, nil
	}
	addressLines, err := buildAddressLines(cfg)
	if err != nil {
		return "", err
	}
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", fmt.Errorf("generate private key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(confPath), 0o700); err != nil {
		return "", fmt.Errorf("create wireguard config dir: %w", err)
	}
	content := buildConfigContent(privateKey.String(), addressLines, cfg.WGListenPort, cfg)
	if err := os.WriteFile(confPath, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("write wireguard config: %w", err)
	}
	return confPath, nil
}

// checkExistingConfig returns (true, nil) if config file already exists and is a file; (false, nil) if not exist; (false, err) on error.
func checkExistingConfig(confPath string) (bool, error) {
	info, err := os.Stat(confPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat wireguard config: %w", err)
	}
	if info.IsDir() {
		return false, fmt.Errorf("wireguard config path is a directory: %s", confPath)
	}
	return true, nil
}

func buildAddressLines(cfg config.Config) ([]string, error) {
	var lines []string
	if cfg.WGSubnet != "" {
		addr, err := addressLineFromSubnet4(cfg.WGSubnet, cfg.WGServerIP)
		if err != nil {
			return nil, err
		}
		lines = append(lines, addr)
	}
	if cfg.WGSubnet6 != "" {
		addr, err := addressLineFromSubnet6(cfg.WGSubnet6, cfg.WGServerIP6)
		if err != nil {
			return nil, err
		}
		lines = append(lines, addr)
	}
	return lines, nil
}

func addressLineFromSubnet4(subnetStr, serverIP string) (string, error) {
	_, subnet, err := net.ParseCIDR(subnetStr)
	if err != nil {
		return "", fmt.Errorf("invalid WG_SUBNET: %w", err)
	}
	if subnet.IP.To4() == nil {
		return "", errors.New("wireguard.subnet must be IPv4")
	}
	ip, err := resolveServerIP4(subnet, serverIP)
	if err != nil {
		return "", err
	}
	maskOnes, _ := subnet.Mask.Size()
	return fmt.Sprintf("%s/%d", ip.String(), maskOnes), nil
}

func addressLineFromSubnet6(subnetStr, serverIP string) (string, error) {
	_, subnet, err := net.ParseCIDR(subnetStr)
	if err != nil {
		return "", fmt.Errorf("invalid WG_SUBNET6: %w", err)
	}
	if subnet.IP.To4() != nil {
		return "", errors.New("wireguard.subnet6 must be IPv6")
	}
	ip, err := resolveServerIP6(subnet, serverIP)
	if err != nil {
		return "", err
	}
	maskOnes, _ := subnet.Mask.Size()
	return fmt.Sprintf("%s/%d", ip.String(), maskOnes), nil
}

func buildConfigContent(privateKey string, addressLines []string, listenPort int, cfg config.Config) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[Interface]\nPrivateKey = %s\n", privateKey))
	for _, a := range addressLines {
		sb.WriteString(fmt.Sprintf("Address = %s\n", a))
	}
	sb.WriteString(fmt.Sprintf("ListenPort = %d\n", listenPort))
	postUp, postDown := buildRoutingRules(cfg)
	if len(postUp) > 0 {
		sb.WriteString("PostUp = " + strings.Join(postUp, "; ") + "\n")
		sb.WriteString("PostDown = " + strings.Join(postDown, "; ") + "\n")
	}
	return sb.String()
}

func buildRoutingRules(cfg config.Config) (postUp, postDown []string) {
	wanInterface := strings.TrimSpace(cfg.WANInterface)
	if wanInterface == "" {
		return nil, nil
	}
	if cfg.WGSubnet != "" {
		postUp = append(postUp,
			fmt.Sprintf("iptables -A FORWARD -i %%i -o %s -s %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet),
			fmt.Sprintf("iptables -A FORWARD -i %s -o %%i -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet),
			fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE", cfg.WGSubnet, wanInterface))
		postDown = append(postDown,
			fmt.Sprintf("iptables -D FORWARD -i %%i -o %s -s %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet),
			fmt.Sprintf("iptables -D FORWARD -i %s -o %%i -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet),
			fmt.Sprintf("iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE", cfg.WGSubnet, wanInterface))
	}
	if cfg.WGSubnet6 != "" {
		postUp = append(postUp,
			fmt.Sprintf("ip6tables -A FORWARD -i %%i -o %s -s %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet6),
			fmt.Sprintf("ip6tables -A FORWARD -i %s -o %%i -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet6),
			fmt.Sprintf("ip6tables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE", cfg.WGSubnet6, wanInterface))
		postDown = append(postDown,
			fmt.Sprintf("ip6tables -D FORWARD -i %%i -o %s -s %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet6),
			fmt.Sprintf("ip6tables -D FORWARD -i %s -o %%i -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet6),
			fmt.Sprintf("ip6tables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE", cfg.WGSubnet6, wanInterface))
	}
	return postUp, postDown
}

func defaultConfigPath(iface string) string {
	if iface == "" {
		iface = "wg0"
	}
	if os.Geteuid() == 0 {
		return filepath.Join("/etc/wireguard", iface+".conf")
	}
	return filepath.Join("wireguard", iface+".conf")
}
