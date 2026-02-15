package server

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const requestIDHeader = "X-Request-Id"
const requestIDKey = "request_id"

type requestIDCtxKey struct{}

// requestIDMiddleware generates a request ID (UUID v4), sets it in the gin context,
// in the request context, and in the response header X-Request-Id so that logs and
// external monitoring (e.g. Prometheus, OpenTelemetry) can correlate requests.
func requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(requestIDHeader)
		if id == "" {
			id = uuid.New().String()
		}
		c.Set(requestIDKey, id)
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), requestIDCtxKey{}, id))
		c.Header(requestIDHeader, id)
		c.Next()
	}
}

// GetRequestID returns the request ID from the gin context, or empty string if not set.
func GetRequestID(c *gin.Context) string {
	id, _ := c.Get(requestIDKey)
	s, _ := id.(string)
	return s
}

// GetRequestIDFromContext returns the request ID from the request context.
// Useful for log formatters and monitoring that only have access to http.Request.
func GetRequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDCtxKey{}).(string)
	return id
}
