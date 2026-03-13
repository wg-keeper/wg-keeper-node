package server

import (
	"bytes"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// MaxRequestBodySize is the maximum size of a request body (e.g. POST /peers).
const MaxRequestBodySize = 256 * 1024 // 256 KB

// bodyLimitMiddleware limits request body size for methods that may send a body.
// Returns 413 Request Entity Too Large if body exceeds MaxRequestBodySize.
func bodyLimitMiddleware(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body == nil {
			c.Next()
			return
		}
		// Only limit methods that typically have a body.
		switch c.Request.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
			// Read up to maxBytes+1 to detect overflow without pre-allocating the full buffer.
			limited := io.LimitReader(c.Request.Body, maxBytes+1)
			buf, err := io.ReadAll(limited)
			if err != nil {
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}
			_ = c.Request.Body.Close()
			if int64(len(buf)) > maxBytes {
				c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
					"error": "request body too large",
					"code":  "body_too_large",
				})
				return
			}
			c.Request.Body = io.NopCloser(bytes.NewReader(buf))
		}
		c.Next()
	}
}
