package server

import (
	"github.com/gin-gonic/gin"
)

// securityHeadersMiddleware sets HTTP security headers on all responses.
func securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		// HSTS only when TLS is used; caller may set Strict-Transport-Security separately or we set a safe default
		// that tells browsers to upgrade for 1 year only if the request was already HTTPS
		if c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		c.Next()
	}
}
