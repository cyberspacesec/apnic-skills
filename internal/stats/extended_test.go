package stats

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseExtendedFull(t *testing.T) {
	result, err := parseExtendedFull(strings.NewReader(sampleExtendedData))
	if err != nil {
		t.Fatalf("parseExtendedFull() error: %v", err)
	}
	if result.Header.Version != "2.3" {
		t.Errorf("header version = %q, want 2.3", result.Header.Version)
	}
	if len(result.Summaries) != 3 {
		t.Errorf("summaries = %d, want 3", len(result.Summaries))
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
	for _, e := range result.Entries {
		if e.OpaqueID == "" {
			t.Error("expected non-empty OpaqueID in extended entry")
			break
		}
	}
	found := false
	for _, e := range result.Entries {
		if e.OpaqueID == "A91872ED" {
			found = true
			if e.Country != "AU" {
				t.Errorf("A91872ED country = %q, want AU", e.Country)
			}
		}
	}
	if !found {
		t.Error("expected to find entry with OpaqueID A91872ED")
	}
}

func TestParseExtendedFullFromString(t *testing.T) {
	result, err := parseExtendedFullFromString(sampleExtendedData)
	if err != nil {
		t.Fatalf("parseExtendedFullFromString() error: %v", err)
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
}

func TestParseExtendedFullEdgeCases(t *testing.T) {
	// Test comment lines, empty lines, short lines, invalid values, unknown type
	data := `2.3|apnic|20260627|5|19850701|20260626|+1000
# comment

apnic|*|asn|*|100|summary
apnic|AU|ipv4|1.0.0.0|invalid|20110811|assigned|A91872ED
apnic|AU|unknown|1.0.1.0|256|20110811|allocated|A92E1062
shortline
apnic|CN|ipv4|1.0.2.0|256|20110414|allocated|A92E1062
`
	result, err := parseExtendedFull(strings.NewReader(data))
	if err != nil {
		t.Fatalf("parseExtendedFull() error: %v", err)
	}
	// Only CN ipv4 should be valid
	if len(result.Entries) != 1 {
		t.Errorf("entries = %d, want 1", len(result.Entries))
	}
}

func TestFetchExtendedEntries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(sampleExtendedData))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	result, err := client.FetchExtendedEntries(context.Background())
	if err != nil {
		t.Fatalf("FetchExtendedEntries() error: %v", err)
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
}

func TestFetchExtendedEntriesByDate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveDated(w, r, sampleExtendedData)
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	result, err := client.FetchExtendedEntriesByDate(context.Background(), "20260627")
	if err != nil {
		t.Fatalf("FetchExtendedEntriesByDate() error: %v", err)
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
}

func TestFetchExtendedResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(sampleExtendedData))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	result, err := client.FetchExtendedResult(context.Background(), "")
	if err != nil {
		t.Fatalf("FetchExtendedResult() error: %v", err)
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
}

func TestFetchExtendedResultByYear(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveDated(w, r, sampleExtendedData)
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	result, err := client.FetchExtendedResultByYear(context.Background(), 2026)
	if err != nil {
		t.Fatalf("FetchExtendedResultByYear() error: %v", err)
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
}

func TestFetchExtendedResultHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	_, err := client.FetchExtendedResult(context.Background(), "")
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}

func TestFetchExtendedResultByYearHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	_, err := client.FetchExtendedResultByYear(context.Background(), 2026)
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}

func TestGetExtendedEntriesWithCache(t *testing.T) {
	client := NewClient(WithCacheTTL(1 * time.Hour))
	entries := []DelegatedExtendedEntry{
		{OpaqueID: "A1", Country: "AU"},
	}
	client.cache.set(cacheKeyExtended, entries)

	result, err := client.GetExtendedEntries(context.Background())
	if err != nil {
		t.Fatalf("GetExtendedEntries() error: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("cached entries count = %d, want 1", len(result))
	}
}

func TestGetExtendedEntriesFetchPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(sampleExtendedData))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Nanosecond),
	)

	result, err := client.GetExtendedEntries(context.Background())
	if err != nil {
		t.Fatalf("GetExtendedEntries() error: %v", err)
	}
	if len(result) == 0 {
		t.Error("expected entries from fetch path")
	}
}

func TestGetExtendedEntriesFetchError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Nanosecond),
	)

	_, err := client.GetExtendedEntries(context.Background())
	if err == nil {
		t.Error("expected error for fetch failure in GetExtendedEntries")
	}
}
