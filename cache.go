package apnic

import (
	"context"
	"sync"
	"time"
)

type cache struct {
	mu               sync.RWMutex
	delegatedEntries []DelegatedEntry
	lastUpdated      time.Time
	ttl              time.Duration
}

func (c *Client) GetDelegatedEntries(ctx context.Context) ([]DelegatedEntry, error) {
	c.cache.mu.RLock()
	if time.Since(c.cache.lastUpdated) < c.cache.ttl && len(c.cache.delegatedEntries) > 0 {
		entries := c.cache.delegatedEntries
		c.cache.mu.RUnlock()
		return entries, nil
	}
	c.cache.mu.RUnlock()

	entries, err := c.FetchDelegatedEntries(ctx)
	if err != nil {
		return nil, err
	}

	c.cache.mu.Lock()
	defer c.cache.mu.Unlock()
	c.cache.delegatedEntries = entries
	c.cache.lastUpdated = time.Now()
	return entries, nil
}
