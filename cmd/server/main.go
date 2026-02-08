package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/wg-keeper/wg-keeper-node/internal/config"
	"github.com/wg-keeper/wg-keeper-node/internal/server"
	"github.com/wg-keeper/wg-keeper-node/internal/version"
	"github.com/wg-keeper/wg-keeper-node/internal/wireguard"

	"github.com/gin-gonic/gin"
)

const (
	cmdInit      = "init"
	argPrintPath = "--print-path"
)

func main() {
	debug := isDebugEnabled()
	setupGinMode(debug)
	log.SetFlags(0)

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("time=%s level=error msg=\"load config\" error=%v", time.Now().Format(time.RFC3339), err)
	}

	if handled, err := handleInit(cfg, os.Args); handled {
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	if _, err := wireguard.EnsureWireGuardConfig(cfg); err != nil {
		log.Fatalf("ensure WireGuard config: %v", err)
	}

	wgService, err := wireguard.NewWireGuardService(cfg)
	if err != nil {
		log.Fatalf("init WireGuard: %v", err)
	}

	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()
	go wgService.RunExpiredPeersCleanup(appCtx, time.Minute)

	addr := cfg.Addr()
	now := time.Now().Format(time.RFC3339)
	protocol := protocolFromConfig(cfg)
	log.Printf("time=%s level=info msg=\"starting\" service=%s version=%s", now, version.Name, version.Version)
	log.Printf("time=%s level=info msg=\"listening\" addr=%s protocol=%s", now, addr, protocol)
	log.Printf("time=%s level=info msg=\"wireguard ready\" iface=%s listen=%d subnets=%s", now, cfg.WGInterface, cfg.WGListenPort, formatSubnetsLog(cfg))
	httpServer := newHTTPServer(cfg, addr, wgService, debug)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- runServer(cfg, httpServer)
	}()

	shutdownSignal := make(chan os.Signal, 1)
	signal.Notify(shutdownSignal, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		if isFatalServerError(err) {
			log.Fatalf("time=%s level=error msg=\"server error\" error=%v", time.Now().Format(time.RFC3339), err)
		}
	case sig := <-shutdownSignal:
		log.Printf("time=%s level=info msg=\"shutdown signal received\" signal=%s", time.Now().Format(time.RFC3339), sig)
	}

	appCancel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("time=%s level=error msg=\"shutdown error\" error=%v", time.Now().Format(time.RFC3339), err)
	}
}

func setupGinMode(debug bool) {
	if debug {
		log.Printf("time=%s level=warn msg=\"DEBUG is enabled; do not use in production (error details exposed to clients)\"", time.Now().Format(time.RFC3339))
		gin.SetMode(gin.DebugMode)
		return
	}
	gin.SetMode(gin.ReleaseMode)
}

func formatSubnetsLog(cfg config.Config) string {
	if cfg.WGSubnet6 == "" {
		return cfg.WGSubnet
	}
	if cfg.WGSubnet != "" {
		return cfg.WGSubnet + "," + cfg.WGSubnet6
	}
	return cfg.WGSubnet6
}

func protocolFromConfig(cfg config.Config) string {
	if cfg.TLSEnabled() {
		return "https"
	}
	return "http"
}

func isFatalServerError(err error) bool {
	return err != nil && err != http.ErrServerClosed
}

func newHTTPServer(cfg config.Config, addr string, wgService *wireguard.WireGuardService, debug bool) *http.Server {
	srv := &http.Server{
		Addr:              addr,
		Handler:           server.NewRouter(cfg.APIKey, cfg.AllowedNets, wgService, debug),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:      30 * time.Second,
		WriteTimeout:     30 * time.Second,
		IdleTimeout:      120 * time.Second,
	}
	if cfg.TLSEnabled() {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return srv
}

func runServer(cfg config.Config, srv *http.Server) error {
	if cfg.TLSEnabled() {
		return srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
	}
	return srv.ListenAndServe()
}

func handleInit(cfg config.Config, args []string) (bool, error) {
	if len(args) < 2 {
		return false, nil
	}
	if args[1] != cmdInit {
		return true, fmt.Errorf("unknown command: %s; use: no args (run server) or init [--print-path]", args[1])
	}

	path, err := wireguard.EnsureWireGuardConfig(cfg)
	if err != nil {
		return true, err
	}
	if len(args) > 2 && args[2] == argPrintPath {
		fmt.Println(path)
		return true, nil
	}
	log.Printf("WireGuard config ready at %s", path)
	return true, nil
}

func isDebugEnabled() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv("DEBUG")))
	return v == "true" || v == "1"
}
