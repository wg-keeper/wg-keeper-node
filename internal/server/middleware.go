package server

import (
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
	if c.GetHeader(apiKeyHeader) == apiKey {
		return true
	}
	return false
}
