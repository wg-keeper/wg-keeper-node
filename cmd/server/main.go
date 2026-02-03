package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
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
	gin.SetMode(gin.ReleaseMode)
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

	addr := cfg.Addr()
	now := time.Now().Format(time.RFC3339)
	log.Printf("time=%s level=info msg=\"starting\" service=%s version=%s", now, version.Name, version.Version)
	log.Printf("time=%s level=info msg=\"listening\" addr=%s", now, addr)
	log.Printf("time=%s level=info msg=\"wireguard ready\" iface=%s listen=%d subnet=%s", now, cfg.WGInterface, cfg.WGListenPort, cfg.WGSubnet)
	router := server.NewRouter(cfg.APIKey, wgService)
	httpServer := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- httpServer.ListenAndServe()
	}()

	shutdownSignal := make(chan os.Signal, 1)
	signal.Notify(shutdownSignal, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("time=%s level=error msg=\"server error\" error=%v", time.Now().Format(time.RFC3339), err)
		}
	case sig := <-shutdownSignal:
		log.Printf("time=%s level=info msg=\"shutdown signal received\" signal=%s", time.Now().Format(time.RFC3339), sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("time=%s level=error msg=\"shutdown error\" error=%v", time.Now().Format(time.RFC3339), err)
	}
}

func handleInit(cfg config.Config, args []string) (bool, error) {
	if len(args) < 2 {
		return false, nil
	}
	if args[1] != cmdInit {
		return true, fmt.Errorf("unknown command: %s", args[1])
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
