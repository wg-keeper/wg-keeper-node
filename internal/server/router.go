package server

import (
	"fmt"
	"time"

	"github.com/wg-keeper/wg-keeper-node/internal/wireguard"

	"github.com/gin-gonic/gin"
)

func NewRouter(apiKey string, wgService *wireguard.WireGuardService) *gin.Engine {
	router := gin.New()
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
	registerRoutes(router, apiKey, wgService)
	return router
}

func registerRoutes(router *gin.Engine, apiKey string, wgService *wireguard.WireGuardService) {
	router.GET("/health", healthHandler)
	router.GET("/stats", apiKeyMiddleware(apiKey), statsHandler(wgService))

	peers := router.Group("/peers", apiKeyMiddleware(apiKey))
	peers.POST("", createPeerHandler(wgService))
	peers.DELETE("/:peerId", deletePeerHandler(wgService))
}
