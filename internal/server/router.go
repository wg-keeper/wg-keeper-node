package server

import (
	"fmt"
	"net"
	"time"

	"github.com/wg-keeper/wg-keeper-node/internal/wireguard"

	"github.com/gin-gonic/gin"
)

const debugKey = "debug"

func NewRouter(apiKey string, allowedNets []*net.IPNet, wgService *wireguard.WireGuardService, debug bool) *gin.Engine {
	router := gin.New()
	router.Use(debugMiddleware(debug))
	router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf(
			"time=%s level=info msg=\"http request\" method=%s path=%s status=%d latency=%s ip=%s\n",
			param.TimeStamp.Format(time.RFC3339),
			param.Method,
			param.Path,
			param.StatusCode,
			param.Latency,
			param.ClientIP,
		)
	}), gin.Recovery())
	registerRoutes(router, apiKey, allowedNets, wgService, debug)
	return router
}

func debugMiddleware(debug bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(debugKey, debug)
		c.Next()
	}
}

func registerRoutes(router *gin.Engine, apiKey string, allowedNets []*net.IPNet, wgService *wireguard.WireGuardService, debug bool) {
	router.GET("/health", healthHandler)
	router.GET("/stats", ipWhitelistMiddleware(allowedNets), apiKeyMiddleware(apiKey), statsHandler(wgService, debug))

	peers := router.Group("/peers", ipWhitelistMiddleware(allowedNets), apiKeyMiddleware(apiKey))
	peers.GET("", listPeersHandler(wgService, debug))
	peers.GET("/:peerId", getPeerHandler(wgService, debug))
	peers.POST("", createPeerHandler(wgService, debug))
	peers.DELETE("/:peerId", deletePeerHandler(wgService, debug))
}
