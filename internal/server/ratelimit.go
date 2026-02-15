package server

import (
	"net"
	"sync"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// Rate limit: 20 requests per second per IP, burst 30.
// Applied only when server.allowed_ips is not set (see README).
const (
	rateLimitRPS   = 20
	rateLimitBurst = 30
)

type ipRateLimiter struct {
	mu       sync.RWMutex
	limiters map[string]*rate.Limiter
	limit    rate.Limit
	burst    int
}

func newIPRateLimiter(rps float64, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		limit:    rate.Limit(rps),
		burst:    burst,
	}
}

func (i *ipRateLimiter) get(ip string) *rate.Limiter {
	i.mu.RLock()
	lim, ok := i.limiters[ip]
	i.mu.RUnlock()
	if ok {
		return lim
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if lim, ok = i.limiters[ip]; ok {
		return lim
	}
	lim = rate.NewLimiter(i.limit, i.burst)
	i.limiters[ip] = lim
	return lim
}

// rateLimitByIPMiddleware returns a middleware that limits requests per client IP.
// When allowedNets is non-empty (IP whitelist is configured), it returns a no-op:
// rate limiting is not applied so that trusted orchestrator IPs are not limited.
func rateLimitByIPMiddleware(allowedNets []*net.IPNet, limiter *ipRateLimiter) gin.HandlerFunc {
	applyLimit := len(allowedNets) == 0
	return func(c *gin.Context) {
		if !applyLimit {
			c.Next()
			return
		}
		ip := c.ClientIP()
		if !limiter.get(ip).Allow() {
			c.AbortWithStatusJSON(429, gin.H{"error": "too many requests", "code": "rate_limited"})
			return
		}
		c.Next()
	}
}

func newRateLimitMiddleware(allowedNets []*net.IPNet) gin.HandlerFunc {
	return rateLimitByIPMiddleware(allowedNets, newIPRateLimiter(rateLimitRPS, rateLimitBurst))
}
