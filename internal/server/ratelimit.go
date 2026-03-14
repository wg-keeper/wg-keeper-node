package server

import (
	"context"
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
	// rateLimiterCleanupInterval is how often the background goroutine evicts stale entries.
	// Half of TTL ensures stale entries are removed well within the TTL window.
	rateLimiterCleanupInterval = rateLimiterTTL / 2
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

	return lim
}

// startCleanup launches a background goroutine that periodically evicts stale
// per-IP limiters. It exits when ctx is cancelled. This keeps memory bounded
// without blocking the request path.
func (i *ipRateLimiter) startCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				i.mu.Lock()
				i.cleanupLocked(now)
				i.mu.Unlock()
			}
		}
	}()
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

func newRateLimitMiddleware(ctx context.Context, allowedNets []*net.IPNet) gin.HandlerFunc {
	limiter := newIPRateLimiter(rateLimitRPS, rateLimitBurst)
	limiter.startCleanup(ctx, rateLimiterCleanupInterval)
	return rateLimitByIPMiddleware(allowedNets, limiter)
}
