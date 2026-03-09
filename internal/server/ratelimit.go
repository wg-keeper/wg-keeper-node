package server

import (
	"net"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// Rate limit: 20 requests per second per IP, burst 30.
// Applied only when server.allowed_ips is not set (see README).
const (
	rateLimitRPS   = 20
	rateLimitBurst = 30

	// rateLimiterTTL is how long per-IP limiters are kept since last use before eviction.
	rateLimiterTTL = 10 * time.Minute
	// rateLimiterCleanupThreshold triggers a cleanup pass when the number of tracked IPs exceeds this number.
	rateLimiterCleanupThreshold = 10_000
)

type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type ipRateLimiter struct {
	mu       sync.RWMutex
	limiters map[string]*ipLimiter
	limit    rate.Limit
	burst    int
}

func newIPRateLimiter(rps float64, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		limiters: make(map[string]*ipLimiter),
		limit:    rate.Limit(rps),
		burst:    burst,
	}
}

func (i *ipRateLimiter) get(ip string) *rate.Limiter {
	now := time.Now()

	i.mu.RLock()
	entry, ok := i.limiters[ip]
	i.mu.RUnlock()
	if ok {
		// Fast path: refresh lastSeen under write lock.
		i.mu.Lock()
		entry.lastSeen = now
		i.mu.Unlock()
		return entry.limiter
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	// Double-check after acquiring write lock.
	if entry, ok = i.limiters[ip]; ok {
		entry.lastSeen = now
		return entry.limiter
	}

	lim := rate.NewLimiter(i.limit, i.burst)
	i.limiters[ip] = &ipLimiter{
		limiter:  lim,
		lastSeen: now,
	}

	if len(i.limiters) > rateLimiterCleanupThreshold {
		i.cleanupLocked(now)
	}

	return lim
}

// cleanupLocked removes stale limiters; caller must hold i.mu.
func (i *ipRateLimiter) cleanupLocked(now time.Time) {
	expireBefore := now.Add(-rateLimiterTTL)
	for key, entry := range i.limiters {
		if entry.lastSeen.Before(expireBefore) {
			delete(i.limiters, key)
		}
	}
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
