package apnic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseDelegatedFull(t *testing.T) {
	result, err := parseDelegatedFull(strings.NewReader(sampleDelegatedData))
	if err != nil {
		t.Fatalf("parseDelegatedFull() error: %v", err)
	}
	if result.Header.Version != "2" {
		t.Errorf("header version = %q, want 2", result.Header.Version)
	}
	if len(result.Summaries) != 3 {
		t.Errorf("summaries count = %d, want 3", len(result.Summaries))
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries, got empty slice")
	}
	found := false
	for _, e := range result.Entries {
		if e.Country == "AU" && e.Type == "ipv4" && e.Start == "1.0.0.0" {
			found = true
			if e.Value != 256 {
				t.Errorf("AU ipv4 value = %d, want 256", e.Value)
			}
			if e.Status != "assigned" {
				t.Errorf("AU ipv4 status = %q, want assigned", e.Status)
			}
		}
	}
	if !found {
		t.Error("expected to find AU ipv4 entry")
	}
}

func TestParseDelegatedFullFromString(t *testing.T) {
	result, err := parseDelegatedFullFromString(sampleDelegatedData)
	if err != nil {
		t.Fatalf("parseDelegatedFullFromString() error: %v", err)
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
}

func TestParseDelegatedData(t *testing.T) {
	result, err := parseDelegatedData(strings.NewReader(sampleDelegatedData))
	if err != nil {
		t.Fatalf("parseDelegatedData() error: %v", err)
	}
	if len(result) == 0 {
		t.Error("expected entries")
	}
}

func TestParseDelegatedFullEdgeCases(t *testing.T) {
	// Test with comment lines, empty lines, short lines, invalid values, unknown types
	data := `2|apnic|20260627|5|19850701|20260626|+1000
# this is a comment

apnic|*|asn|*|100|summary
apnic|AU|ipv4|1.0.0.0|invalidcount|20110811|assigned
apnic|AU|unknown|1.0.2.0|256|20110811|allocated
short|line
apnic|CN|ipv4|1.0.3.0|256|20110414|allocated
`
	result, err := parseDelegatedFull(strings.NewReader(data))
	if err != nil {
		t.Fatalf("parseDelegatedFull() error: %v", err)
	}
	// Invalid count entry is skipped; unknown type entry is skipped;
	// short line is skipped; only CN ipv4 remains
	if len(result.Entries) != 1 {
		t.Errorf("entries = %d, want 1", len(result.Entries))
	}
}

func TestFetchDelegatedEntries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(sampleDelegatedData))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	entries, err := client.FetchDelegatedEntries(context.Background())
	if err != nil {
		t.Fatalf("FetchDelegatedEntries() error: %v", err)
	}
	if len(entries) == 0 {
		t.Error("expected entries")
	}
}

func TestFetchDelegatedEntriesByDate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(sampleDelegatedData))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	entries, err := client.FetchDelegatedEntriesByDate(context.Background(), "20260627")
	if err != nil {
		t.Fatalf("FetchDelegatedEntriesByDate() error: %v", err)
	}
	if len(entries) == 0 {
		t.Error("expected entries")
	}
}

func TestFetchDelegatedResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(sampleDelegatedData))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	result, err := client.FetchDelegatedResult(context.Background(), "")
	if err != nil {
		t.Fatalf("FetchDelegatedResult() error: %v", err)
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
}

func TestFetchDelegatedResultByYear(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(sampleDelegatedData))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	result, err := client.FetchDelegatedResultByYear(context.Background(), 2026)
	if err != nil {
		t.Fatalf("FetchDelegatedResultByYear() error: %v", err)
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
}

func TestFetchDelegatedResultHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	_, err := client.FetchDelegatedResult(context.Background(), "")
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}

func TestFetchDelegatedCancelledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(sampleDelegatedData))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.FetchDelegatedEntries(ctx)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestFetchTextInvalidURL(t *testing.T) {
	client := NewClient(WithStatsBaseURL("http://[::1]:%invalid/"))
	_, err := client.FetchDelegatedEntries(context.Background())
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestGetDelegatedEntriesWithCache(t *testing.T) {
	client := NewClient(WithCacheTTL(1 * time.Hour))
	entries := []DelegatedEntry{
		{Country: "AU", Type: "ipv4", Start: "1.0.0.0", Value: 256},
		{Country: "CN", Type: "ipv4", Start: "1.0.1.0", Value: 256},
	}
	client.cache.set(cacheKeyDelegated, entries)

	result, err := client.GetDelegatedEntries(context.Background())
	if err != nil {
		t.Fatalf("GetDelegatedEntries() error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("cached entries count = %d, want 2", len(result))
	}
}

func TestGetDelegatedEntriesFetchPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(sampleDelegatedData))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Nanosecond), // cache expires immediately
	)

	result, err := client.GetDelegatedEntries(context.Background())
	if err != nil {
		t.Fatalf("GetDelegatedEntries() error: %v", err)
	}
	if len(result) == 0 {
		t.Error("expected entries from fetch path")
	}
}

func TestFetchDelegatedEntriesByDateHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	_, err := client.FetchDelegatedEntriesByDate(context.Background(), "20260627")
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}

func TestFetchDelegatedResultByYearHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	_, err := client.FetchDelegatedResultByYear(context.Background(), 2026)
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}

func TestParseDelegatedDataError(t *testing.T) {
	// parseDelegatedData wraps parseDelegatedFull; test with a reader that returns error
	_, err := parseDelegatedData(errorReader{})
	if err == nil {
		t.Error("expected error from error reader")
	}
}

func TestFetchTextReadError(t *testing.T) {
	// Use a custom RoundTripper that returns a body that errors on read
	client := NewClient(
		WithHTTPClient(&http.Client{Transport: errorRoundTripper{}}),
		WithStatsBaseURL("http://example.com/"),
		WithCacheTTL(1*time.Hour),
	)

	_, err := client.FetchDelegatedEntries(context.Background())
	if err == nil {
		t.Error("expected error for read failure")
	}
}

func TestGetDelegatedEntriesFetchError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Nanosecond),
	)

	_, err := client.GetDelegatedEntries(context.Background())
	if err == nil {
		t.Error("expected error for fetch failure in GetDelegatedEntries")
	}
}
