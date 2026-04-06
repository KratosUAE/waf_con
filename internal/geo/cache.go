// Package geo provides IP geolocation lookups via ipinfo.io with a file-based cache.
package geo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const cacheTTL = 7 * 24 * 3600 // 7 days in seconds.

// GeoEntry is a cached geolocation result for a single IP.
type GeoEntry struct {
	City     string `json:"city"`
	Country  string `json:"country"`
	Org      string `json:"org"`
	CachedAt int64  `json:"cached_at"`
}

// Cache provides a file-backed IP geolocation cache.
type Cache struct {
	mu      sync.Mutex
	entries map[string]GeoEntry
	path    string
}

// NewCache loads or creates a geo cache at the given path.
// If the file does not exist, an empty cache is returned.
func NewCache(path string) (*Cache, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("geo: failed to create cache dir: %w", err)
	}

	c := &Cache{
		entries: make(map[string]GeoEntry),
		path:    path,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, fmt.Errorf("geo: failed to read cache: %w", err)
	}

	if err := json.Unmarshal(data, &c.entries); err != nil {
		// Corrupted cache file -- start fresh.
		return c, nil
	}

	return c, nil
}

// Get returns a cached entry if it exists and has not expired.
func (c *Cache) Get(ip string) (GeoEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[ip]
	if !ok {
		return GeoEntry{}, false
	}

	if time.Now().Unix()-entry.CachedAt >= cacheTTL {
		return GeoEntry{}, false
	}

	return entry, true
}

// Set stores a geo entry with the current timestamp.
func (c *Cache) Set(ip string, entry GeoEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry.CachedAt = time.Now().Unix()
	c.entries[ip] = entry
}

// Save persists the cache to disk atomically using a temp file + rename,
// preventing a corrupt cache file if the process crashes mid-write.
func (c *Cache) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := json.MarshalIndent(c.entries, "", "  ")
	if err != nil {
		return fmt.Errorf("geo: failed to marshal cache: %w", err)
	}

	// Write to a temp file in the same directory so os.Rename is atomic.
	dir := filepath.Dir(c.path)
	tmp, err := os.CreateTemp(dir, "geo-cache-*.json.tmp")
	if err != nil {
		return fmt.Errorf("geo: failed to create temp cache file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("geo: failed to write temp cache file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("geo: failed to close temp cache file: %w", err)
	}

	if err := os.Rename(tmpName, c.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("geo: failed to rename cache file: %w", err)
	}

	return nil
}

// FilterUncached returns only IPs that are not in the cache or have expired.
// Acquires the lock once for the entire slice rather than once per IP.
func (c *Cache) FilterUncached(ips []string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().Unix()
	var uncached []string
	for _, ip := range ips {
		entry, ok := c.entries[ip]
		if !ok || now-entry.CachedAt >= cacheTTL {
			uncached = append(uncached, ip)
		}
	}
	return uncached
}
