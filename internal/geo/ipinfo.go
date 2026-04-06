package geo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"
)

const (
	lookupWorkers       = 5
	lookupTimeout       = 5 * time.Second
	maxResponseBodySize = 4096 // bytes; ipinfo.io JSON responses are small
)

// ipinfoResp is the JSON response from ipinfo.io.
type ipinfoResp struct {
	City    string `json:"city"`
	Country string `json:"country"`
	Org     string `json:"org"`
}

// Lookup resolves geolocation for uncached IPs using ipinfo.io.
// Results are stored in cache and persisted to disk after completion.
// It delegates filtering to cache.FilterUncached to avoid duplicating the logic.
func Lookup(ctx context.Context, cache *Cache, ips []string, token string) error {
	if token == "" {
		return nil
	}

	// Use FilterUncached to get IPs that need resolution, then additionally
	// remove private/loopback addresses which should never be sent to ipinfo.io.
	uncached := cache.FilterUncached(ips)

	var toResolve []string
	for _, ip := range uncached {
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.IsPrivate() || parsed.IsLoopback() {
			continue
		}
		toResolve = append(toResolve, ip)
	}

	if len(toResolve) == 0 {
		return nil
	}

	client := &http.Client{Timeout: lookupTimeout}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(lookupWorkers)

	for _, ip := range toResolve {
		g.Go(func() error {
			entry, err := lookupIP(ctx, client, ip, token)
			if err != nil {
				// Log warning but don't fail the whole batch.
				return nil
			}
			cache.Set(ip, entry)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	return cache.Save()
}

// lookupIP queries ipinfo.io for a single IP.
func lookupIP(ctx context.Context, client *http.Client, ip, token string) (GeoEntry, error) {
	url := fmt.Sprintf("https://ipinfo.io/%s", ip)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return GeoEntry{}, fmt.Errorf("geo: failed to create request for %s: %w", ip, err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return GeoEntry{}, fmt.Errorf("geo: failed to lookup %s: %w", ip, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return GeoEntry{}, fmt.Errorf("geo: rate limited by ipinfo.io")
	}

	if resp.StatusCode != http.StatusOK {
		return GeoEntry{}, fmt.Errorf("geo: ipinfo.io returned %d for %s", resp.StatusCode, ip)
	}

	// Limit response body to prevent unbounded memory consumption from a
	// misbehaving or malicious server response.
	limited := io.LimitReader(resp.Body, maxResponseBodySize)

	var info ipinfoResp
	if err := json.NewDecoder(limited).Decode(&info); err != nil {
		return GeoEntry{}, fmt.Errorf("geo: failed to decode response for %s: %w", ip, err)
	}

	return GeoEntry{
		City:    info.City,
		Country: info.Country,
		Org:     info.Org,
	}, nil
}
