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
	WGInterface  string
	WGSubnet     string
	WGServerIP   string
	WGListenPort int
	WANInterface string
}

type wireguardRouting struct {
	WANInterface string `yaml:"wan_interface"`
}

type fileConfig struct {
	Server struct {
		Port string `yaml:"port"`
	} `yaml:"server"`
	Auth struct {
		APIKey string `yaml:"api_key"`
	} `yaml:"auth"`
	WireGuard struct {
		Interface  string           `yaml:"interface"`
		Subnet     string           `yaml:"subnet"`
		ServerIP   string           `yaml:"server_ip"`
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

	portValue, err := parsePort("server.port", fc.Server.Port)
	if err != nil {
		return Config{}, err
	}
	apiKey, err := requireString("auth.api_key", fc.Auth.APIKey)
	if err != nil {
		return Config{}, err
	}
	wgSubnet, err := requireCIDR("wireguard.subnet", fc.WireGuard.Subnet)
	if err != nil {
		return Config{}, err
	}
	wgInterface, err := requireString("wireguard.interface", fc.WireGuard.Interface)
	if err != nil {
		return Config{}, err
	}
	wgListenPort := fc.WireGuard.ListenPort
	if err := requirePort("wireguard.listen_port", wgListenPort); err != nil {
		return Config{}, err
	}
	wgServerIP, err := optionalIPv4("wireguard.server_ip", fc.WireGuard.ServerIP)
	if err != nil {
		return Config{}, err
	}
	wanInterface, err := requireString("wireguard.routing.wan_interface", fc.WireGuard.Routing.WANInterface)
	if err != nil {
		return Config{}, err
	}

	return Config{
		Port:         portValue,
		APIKey:       apiKey,
		WGInterface:  wgInterface,
		WGSubnet:     wgSubnet,
		WGServerIP:   wgServerIP,
		WGListenPort: wgListenPort,
		WANInterface: wanInterface,
	}, nil
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

func requireCIDR(field, value string) (string, error) {
	out := strings.TrimSpace(value)
	if out == "" {
		return "", fmt.Errorf(errMsgRequired, field)
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
