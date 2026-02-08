package server

import (
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
)

const apiKeyHeader = "X-API-Key"

func apiKeyMiddleware(apiKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if apiKey == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "api key is not configured"})
			c.Abort()
			return
		}

		if !apiKeyMatches(c, apiKey) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func apiKeyMatches(c *gin.Context, apiKey string) bool {
	return c.GetHeader(apiKeyHeader) == apiKey
}

// ipWhitelistMiddleware blocks requests whose ClientIP is not in any of the allowed nets.
// If allowedNets is nil or empty, all requests are allowed (no whitelist).
func ipWhitelistMiddleware(allowedNets []*net.IPNet) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(allowedNets) == 0 {
			c.Next()
			return
		}
		clientIP := net.ParseIP(c.ClientIP())
		if clientIP == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "client IP could not be determined"})
			c.Abort()
			return
		}
		for _, n := range allowedNets {
			if n.Contains(clientIP) {
				c.Next()
				return
			}
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden: IP not allowed"})
		c.Abort()
	}
}
