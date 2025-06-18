package main

import (
	"container/list"
	"sync"
	"time"
)

// SlidingWindowRateLimiter is a rate limiter that uses a sliding window algorithm.
type SlidingWindowRateLimiter struct {
	mu          sync.Mutex
	windowSize  time.Duration
	maxRequests int
	requests    *list.List
}

// NewSlidingWindowRateLimiter creates a new SlidingWindowRateLimiter.
func NewSlidingWindowRateLimiter(windowSize time.Duration, maxRequests int) *SlidingWindowRateLimiter {
	return &SlidingWindowRateLimiter{
		windowSize:  windowSize,
		maxRequests: maxRequests,
		requests:    list.New(),
	}
}

// Allow checks if a new request can be allowed within the rate limit.
func (l *SlidingWindowRateLimiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for l.requests.Len() > 0 {
		front := l.requests.Front()
		if now.Sub(front.Value.(time.Time)) > l.windowSize {
			l.requests.Remove(front)
		} else {
			break
		}
	}

	if l.requests.Len() < l.maxRequests {
		l.requests.PushBack(now)
		return true
	}
	return false
}
