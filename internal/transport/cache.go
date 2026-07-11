package transport

import (
	"context"
	"sync"
	"time"
)

// cacheEntry holds cached data with its last update time.
type cacheEntry struct {
	data        interface{}
	lastUpdated time.Time
}

// cache provides thread-safe caching for multiple data types.
type cache struct {
	mu   sync.RWMutex
	ttl  time.Duration
	data map[string]cacheEntry
}

// newCache creates a new cache with the specified TTL.
func newCache(ttl time.Duration) *cache {
	return &cache{
		ttl:  ttl,
		data: make(map[string]cacheEntry),
	}
}

// get retrieves data from cache if it exists and has not expired.
func (c *cache) get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.data[key]
	if !ok || time.Since(entry.lastUpdated) >= c.ttl {
		return nil, false
	}
	return entry.data, true
}

// set stores data in cache with the current timestamp.
func (c *cache) set(key string, data interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = cacheEntry{
		data:        data,
		lastUpdated: time.Now(),
	}
}

// Cache key constants for different data types.
const (
	cacheKeyDelegated      = "delegated"
	cacheKeyExtended       = "extended"
	cacheKeyAssigned       = "assigned"
	cacheKeyIPv6Assigned   = "ipv6-assigned"
	cacheKeyLegacy         = "legacy"
	cacheKeyTransfers      = "transfers"
	cacheKeyChanges        = "changes"
)

// cacheKeyIRR returns the cache key for an IRR database of the given object type.
func cacheKeyIRR(objType string) string {
	return "irr:" + objType
}

// GetDelegatedEntries returns cached delegated entries, fetching fresh data if expired.
func (c *Client) GetDelegatedEntries(ctx context.Context) ([]DelegatedEntry, error) {
	if data, ok := c.cache.get(cacheKeyDelegated); ok {
		return data.([]DelegatedEntry), nil
	}

	entries, err := c.FetchDelegatedEntries(ctx)
	if err != nil {
		return nil, err
	}

	c.cache.set(cacheKeyDelegated, entries)
	return entries, nil
}

// GetExtendedEntries returns cached extended delegated entries, fetching fresh data if expired.
func (c *Client) GetExtendedEntries(ctx context.Context) ([]DelegatedExtendedEntry, error) {
	if data, ok := c.cache.get(cacheKeyExtended); ok {
		return data.([]DelegatedExtendedEntry), nil
	}

	result, err := c.FetchExtendedEntries(ctx)
	if err != nil {
		return nil, err
	}

	c.cache.set(cacheKeyExtended, result.Entries)
	return result.Entries, nil
}

// GetAssignedEntries returns cached assigned entries, fetching fresh data if expired.
func (c *Client) GetAssignedEntries(ctx context.Context) ([]AssignedEntry, error) {
	if data, ok := c.cache.get(cacheKeyAssigned); ok {
		return data.([]AssignedEntry), nil
	}

	result, err := c.FetchAssignedEntries(ctx)
	if err != nil {
		return nil, err
	}

	c.cache.set(cacheKeyAssigned, result.Entries)
	return result.Entries, nil
}

// GetIPv6AssignedEntries returns cached IPv6 assigned entries, fetching fresh data if expired.
func (c *Client) GetIPv6AssignedEntries(ctx context.Context) ([]IPv6AssignedEntry, error) {
	if data, ok := c.cache.get(cacheKeyIPv6Assigned); ok {
		return data.([]IPv6AssignedEntry), nil
	}

	entries, err := c.FetchIPv6AssignedEntries(ctx)
	if err != nil {
		return nil, err
	}

	c.cache.set(cacheKeyIPv6Assigned, entries)
	return entries, nil
}

// GetLegacyEntries returns cached legacy entries, fetching fresh data if expired.
func (c *Client) GetLegacyEntries(ctx context.Context) ([]LegacyEntry, error) {
	if data, ok := c.cache.get(cacheKeyLegacy); ok {
		return data.([]LegacyEntry), nil
	}

	result, err := c.FetchLegacyEntries(ctx)
	if err != nil {
		return nil, err
	}

	c.cache.set(cacheKeyLegacy, result.Entries)
	return result.Entries, nil
}

// GetTransfers returns cached transfer records, fetching fresh data if expired.
func (c *Client) GetTransfers(ctx context.Context) (*TransfersResult, error) {
	if data, ok := c.cache.get(cacheKeyTransfers); ok {
		return data.(*TransfersResult), nil
	}

	result, err := c.FetchTransfers(ctx)
	if err != nil {
		return nil, err
	}

	c.cache.set(cacheKeyTransfers, result)
	return result, nil
}

// GetChanges returns cached change records, fetching fresh data if expired.
func (c *Client) GetChanges(ctx context.Context) (*ChangesResult, error) {
	if data, ok := c.cache.get(cacheKeyChanges); ok {
		return data.(*ChangesResult), nil
	}

	result, err := c.FetchChanges(ctx)
	if err != nil {
		return nil, err
	}

	c.cache.set(cacheKeyChanges, result)
	return result, nil
}

// GetIRRDatabase returns a cached IRR database for the given object type,
// fetching fresh data if expired or absent. objType must be a known IRR object
// type (see IRRObjectTypes).
func (c *Client) GetIRRDatabase(ctx context.Context, objType string) (*IRRDatabase, error) {
	if data, ok := c.cache.get(cacheKeyIRR(objType)); ok {
		return data.(*IRRDatabase), nil
	}

	result, err := c.FetchIRRDatabase(ctx, objType)
	if err != nil {
		return nil, err
	}

	c.cache.set(cacheKeyIRR(objType), result)
	return result, nil
}
