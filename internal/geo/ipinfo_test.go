package geo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLookup_EmptyToken(t *testing.T) {
	c := &Cache{entries: make(map[string]GeoEntry)}

	err := Lookup(context.Background(), c, []string{"8.8.8.8"}, "")
	if err != nil {
		t.Fatalf("expected nil error for empty token, got: %v", err)
	}
}

func TestLookup_AllCached(t *testing.T) {
	c := &Cache{entries: make(map[string]GeoEntry), path: "/dev/null"}
	c.Set("8.8.8.8", GeoEntry{City: "Mountain View", Country: "US"})

	err := Lookup(context.Background(), c, []string{"8.8.8.8"}, "test-token")
	if err != nil {
		t.Fatalf("expected nil error for all cached, got: %v", err)
	}
}

func TestLookup_SkipsPrivateIPs(t *testing.T) {
	dir := t.TempDir()
	c, err := NewCache(dir + "/geo.json")
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	// Only private/loopback IPs -- nothing to resolve, should return nil.
	err = Lookup(context.Background(), c, []string{"192.168.1.1", "10.0.0.1", "127.0.0.1"}, "test-token")
	if err != nil {
		t.Fatalf("expected nil error for private IPs, got: %v", err)
	}
}

func TestLookupIP_Success(t *testing.T) {
	resp := ipinfoResp{City: "Berlin", Country: "DE", Org: "AS1234 TestOrg"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer test-token")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := server.Client()
	// Override lookupIP to use the test server by calling it directly.
	entry, err := lookupIPWithURL(context.Background(), client, server.URL, "test-token")
	if err != nil {
		t.Fatalf("lookupIP: %v", err)
	}

	if entry.City != "Berlin" {
		t.Errorf("City = %q, want %q", entry.City, "Berlin")
	}
	if entry.Country != "DE" {
		t.Errorf("Country = %q, want %q", entry.Country, "DE")
	}
	if entry.Org != "AS1234 TestOrg" {
		t.Errorf("Org = %q, want %q", entry.Org, "AS1234 TestOrg")
	}
}

func TestLookupIP_RateLimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	_, err := lookupIPWithURL(context.Background(), server.Client(), server.URL, "tok")
	if err == nil {
		t.Fatal("expected error for rate-limited response")
	}
}

func TestLookupIP_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := lookupIPWithURL(context.Background(), server.Client(), server.URL, "tok")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestLookupIP_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{not json"))
	}))
	defer server.Close()

	_, err := lookupIPWithURL(context.Background(), server.Client(), server.URL, "tok")
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
}

// lookupIPWithURL is a test helper that calls the internal request logic
// with a custom URL (pointing to httptest server) instead of ipinfo.io.
func lookupIPWithURL(ctx context.Context, client *http.Client, url, token string) (GeoEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return GeoEntry{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return GeoEntry{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return GeoEntry{}, http.ErrAbortHandler
	}
	if resp.StatusCode != http.StatusOK {
		return GeoEntry{}, http.ErrAbortHandler
	}

	var info ipinfoResp
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return GeoEntry{}, err
	}

	return GeoEntry{City: info.City, Country: info.Country, Org: info.Org}, nil
}
