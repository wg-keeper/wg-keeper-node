package server

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// MaxRequestBodySize is the maximum size of a request body (e.g. POST /peers).
const MaxRequestBodySize = 256 * 1024 // 256 KB

// bodyLimitMiddleware limits request body size for all HTTP methods.
// http.MaxBytesReader is applied universally to guard against oversized chunked
// bodies on any method. For POST/PUT/PATCH the body is also read eagerly so
// that an oversized payload is rejected with 413 before reaching the handler.
func bodyLimitMiddleware(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body == nil {
			c.Next()
			return
		}
		// Wrap with MaxBytesReader for all methods — this covers chunked transfer
		// encoding on GET, DELETE, and any other method.
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		switch c.Request.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
			buf, err := io.ReadAll(c.Request.Body)
			if err != nil {
				var maxBytesErr *http.MaxBytesError
				if errors.As(err, &maxBytesErr) {
					c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
						"error": "request body too large",
						"code":  "body_too_large",
					})
					return
				}
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}
			_ = c.Request.Body.Close()
			c.Request.Body = io.NopCloser(bytes.NewReader(buf))
		}
		c.Next()
	}
}
