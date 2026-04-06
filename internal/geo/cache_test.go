package geo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewCache_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geo.json")

	c, err := newTestCache(path)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	if _, ok := c.Get("1.2.3.4"); ok {
		t.Error("expected empty cache to return false")
	}
}

func TestNewCache_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geo.json")

	entries := map[string]GeoEntry{
		"8.8.8.8": {City: "Mountain View", Country: "US", Org: "Google", CachedAt: time.Now().Unix()},
	}
	data, _ := json.Marshal(entries)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c, err := newTestCache(path)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	entry, ok := c.Get("8.8.8.8")
	if !ok {
		t.Fatal("expected cached entry for 8.8.8.8")
	}
	if entry.City != "Mountain View" {
		t.Errorf("City = %q, want %q", entry.City, "Mountain View")
	}
}

func TestNewCache_CorruptedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geo.json")

	if err := os.WriteFile(path, []byte("{bad json"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c, err := newTestCache(path)
	if err != nil {
		t.Fatalf("NewCache should not fail on corrupted file: %v", err)
	}

	if _, ok := c.Get("1.1.1.1"); ok {
		t.Error("corrupted cache should be empty")
	}
}

func TestCache_GetSet(t *testing.T) {
	c := &Cache{entries: make(map[string]GeoEntry)}

	c.Set("1.1.1.1", GeoEntry{City: "Sydney", Country: "AU", Org: "Cloudflare"})

	entry, ok := c.Get("1.1.1.1")
	if !ok {
		t.Fatal("expected entry after Set")
	}
	if entry.Country != "AU" {
		t.Errorf("Country = %q, want %q", entry.Country, "AU")
	}
}

func TestCache_GetExpired(t *testing.T) {
	c := &Cache{entries: make(map[string]GeoEntry)}

	c.entries["1.1.1.1"] = GeoEntry{
		City:     "Sydney",
		Country:  "AU",
		Org:      "Cloudflare",
		CachedAt: time.Now().Unix() - cacheTTL - 1,
	}

	if _, ok := c.Get("1.1.1.1"); ok {
		t.Error("expected expired entry to return false")
	}
}

func TestCache_GetMissing(t *testing.T) {
	c := &Cache{entries: make(map[string]GeoEntry)}

	if _, ok := c.Get("9.9.9.9"); ok {
		t.Error("expected missing entry to return false")
	}
}

func TestCache_SaveAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geo.json")

	c, err := newTestCache(path)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	c.Set("8.8.4.4", GeoEntry{City: "Mountain View", Country: "US", Org: "Google"})

	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reload from disk.
	c2, err := newTestCache(path)
	if err != nil {
		t.Fatalf("NewCache reload: %v", err)
	}

	entry, ok := c2.Get("8.8.4.4")
	if !ok {
		t.Fatal("expected entry after reload")
	}
	if entry.City != "Mountain View" {
		t.Errorf("City = %q, want %q", entry.City, "Mountain View")
	}
}

func TestCache_FilterUncached(t *testing.T) {
	c := &Cache{entries: make(map[string]GeoEntry)}
	c.Set("1.1.1.1", GeoEntry{City: "Sydney", Country: "AU"})
	c.Set("8.8.8.8", GeoEntry{City: "Mountain View", Country: "US"})

	tests := []struct {
		name string
		ips  []string
		want int
	}{
		{"all cached", []string{"1.1.1.1", "8.8.8.8"}, 0},
		{"one uncached", []string{"1.1.1.1", "9.9.9.9"}, 1},
		{"all uncached", []string{"2.2.2.2", "3.3.3.3"}, 2},
		{"empty input", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.FilterUncached(tt.ips)
			if len(got) != tt.want {
				t.Errorf("FilterUncached(%v) returned %d IPs, want %d", tt.ips, len(got), tt.want)
			}
		})
	}
}

func newTestCache(path string) (*Cache, error) {
	return NewCache(path)
}
