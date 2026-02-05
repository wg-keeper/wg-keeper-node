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

	_, subnet, err := net.ParseCIDR(cfg.WGSubnet)
	if err != nil {
		return "", fmt.Errorf("invalid WG_SUBNET: %w", err)
	}
	if subnet.IP.To4() == nil {
		return "", errors.New("WG_SUBNET must be IPv4")
	}

	serverIP, err := resolveServerIP(subnet, cfg.WGServerIP)
	if err != nil {
		return "", err
	}

	maskOnes, _ := subnet.Mask.Size()
	address := fmt.Sprintf("%s/%d", serverIP.String(), maskOnes)

	listenPort := cfg.WGListenPort

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", fmt.Errorf("generate private key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(confPath), 0o700); err != nil {
		return "", fmt.Errorf("create wireguard config dir: %w", err)
	}

	content := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nListenPort = %d\n", privateKey.String(), address, listenPort)
	if wanInterface := strings.TrimSpace(cfg.WANInterface); wanInterface != "" {
		postUp := fmt.Sprintf("PostUp = iptables -A FORWARD -i %%i -o %s -s %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT; iptables -A FORWARD -i %s -o %%i -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE\n", wanInterface, cfg.WGSubnet, wanInterface, cfg.WGSubnet, cfg.WGSubnet, wanInterface)
		postDown := fmt.Sprintf("PostDown = iptables -D FORWARD -i %%i -o %s -s %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT; iptables -D FORWARD -i %s -o %%i -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE\n", wanInterface, cfg.WGSubnet, wanInterface, cfg.WGSubnet, cfg.WGSubnet, wanInterface)
		content += postUp + postDown
	}
	if err := os.WriteFile(confPath, []byte(content), 0o600); err != nil {
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
