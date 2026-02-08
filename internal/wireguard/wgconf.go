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

	info, err := os.Stat(confPath)
	if err == nil {
		if info.IsDir() {
			return "", fmt.Errorf("wireguard config path is a directory: %s", confPath)
		}
		return confPath, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat wireguard config: %w", err)
	}

	var addressLines []string
	if cfg.WGSubnet != "" {
		_, subnet, err := net.ParseCIDR(cfg.WGSubnet)
		if err != nil {
			return "", fmt.Errorf("invalid WG_SUBNET: %w", err)
		}
		if subnet.IP.To4() == nil {
			return "", errors.New("wireguard.subnet must be IPv4")
		}
		serverIP, err := resolveServerIP4(subnet, cfg.WGServerIP)
		if err != nil {
			return "", err
		}
		maskOnes, _ := subnet.Mask.Size()
		addressLines = append(addressLines, fmt.Sprintf("%s/%d", serverIP.String(), maskOnes))
	}
	if cfg.WGSubnet6 != "" {
		_, subnet, err := net.ParseCIDR(cfg.WGSubnet6)
		if err != nil {
			return "", fmt.Errorf("invalid WG_SUBNET6: %w", err)
		}
		if subnet.IP.To4() != nil {
			return "", errors.New("wireguard.subnet6 must be IPv6")
		}
		serverIP, err := resolveServerIP6(subnet, cfg.WGServerIP6)
		if err != nil {
			return "", err
		}
		maskOnes, _ := subnet.Mask.Size()
		addressLines = append(addressLines, fmt.Sprintf("%s/%d", serverIP.String(), maskOnes))
	}

	listenPort := cfg.WGListenPort

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", fmt.Errorf("generate private key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(confPath), 0o700); err != nil {
		return "", fmt.Errorf("create wireguard config dir: %w", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[Interface]\nPrivateKey = %s\n", privateKey.String()))
	for _, a := range addressLines {
		sb.WriteString(fmt.Sprintf("Address = %s\n", a))
	}
	sb.WriteString(fmt.Sprintf("ListenPort = %d\n", listenPort))

	wanInterface := strings.TrimSpace(cfg.WANInterface)
	if wanInterface != "" {
		var postUp, postDown []string
		if cfg.WGSubnet != "" {
			postUp = append(postUp, fmt.Sprintf("iptables -A FORWARD -i %%i -o %s -s %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet),
				fmt.Sprintf("iptables -A FORWARD -i %s -o %%i -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet),
				fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE", cfg.WGSubnet, wanInterface))
			postDown = append(postDown, fmt.Sprintf("iptables -D FORWARD -i %%i -o %s -s %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet),
				fmt.Sprintf("iptables -D FORWARD -i %s -o %%i -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet),
				fmt.Sprintf("iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE", cfg.WGSubnet, wanInterface))
		}
		if cfg.WGSubnet6 != "" {
			postUp = append(postUp, fmt.Sprintf("ip6tables -A FORWARD -i %%i -o %s -s %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet6),
				fmt.Sprintf("ip6tables -A FORWARD -i %s -o %%i -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet6),
				fmt.Sprintf("ip6tables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE", cfg.WGSubnet6, wanInterface))
			postDown = append(postDown, fmt.Sprintf("ip6tables -D FORWARD -i %%i -o %s -s %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet6),
				fmt.Sprintf("ip6tables -D FORWARD -i %s -o %%i -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet6),
				fmt.Sprintf("ip6tables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE", cfg.WGSubnet6, wanInterface))
		}
		sb.WriteString("PostUp = " + strings.Join(postUp, "; ") + "\n")
		sb.WriteString("PostDown = " + strings.Join(postDown, "; ") + "\n")
	}

	if err := os.WriteFile(confPath, []byte(sb.String()), 0o600); err != nil {
		return "", fmt.Errorf("write wireguard config: %w", err)
	}

	return confPath, nil
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
