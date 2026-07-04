package apnic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseAssignedFull(t *testing.T) {
	result, err := parseAssignedFull(strings.NewReader(sampleAssignedData))
	if err != nil {
		t.Fatalf("parseAssignedFull() error: %v", err)
	}
	if result.Header.Version != "1" {
		t.Errorf("header version = %q, want 1", result.Header.Version)
	}
	if len(result.Summaries) != 2 {
		t.Errorf("summaries = %d, want 2", len(result.Summaries))
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
}

func TestParseAssignedFullEdgeCases(t *testing.T) {
	data := `1|apnic|20260627|5|19850701|20260626|+1000
# comment

apnic|*|ipv4|*|100|summary
apnic|ae|asn||1||allocated||5
apnic|ae|ipv4||256||assigned||12
shortline
apnic|ae|ipv4||4||assigned||0
`
	result, err := parseAssignedFull(strings.NewReader(data))
	if err != nil {
		t.Fatalf("parseAssignedFull() error: %v", err)
	}
	// Only ipv4 entries should be parsed (asn entries skipped)
	// The entry with count 0 should still be included (parseIPv4Count returns error for 0, count stays 0)
	if len(result.Entries) != 2 {
		t.Errorf("entries = %d, want 2", len(result.Entries))
	}
}

func TestFetchAssignedEntries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(sampleAssignedData))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	result, err := client.FetchAssignedEntries(context.Background())
	if err != nil {
		t.Fatalf("FetchAssignedEntries() error: %v", err)
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
}

func TestFetchAssignedEntriesByDate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveDated(w, r, sampleAssignedData)
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	result, err := client.FetchAssignedEntriesByDate(context.Background(), "20260627")
	if err != nil {
		t.Fatalf("FetchAssignedEntriesByDate() error: %v", err)
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
}

func TestFetchAssignedResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(sampleAssignedData))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	result, err := client.FetchAssignedResult(context.Background(), "")
	if err != nil {
		t.Fatalf("FetchAssignedResult() error: %v", err)
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
}

func TestFetchAssignedResultHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	_, err := client.FetchAssignedResult(context.Background(), "")
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}

func TestGetAssignedEntriesWithCache(t *testing.T) {
	client := NewClient(WithCacheTTL(1 * time.Hour))
	entries := []AssignedEntry{
		{Country: "ae", Type: "ipv4", Prefix: "4", Count: 1},
	}
	client.cache.set(cacheKeyAssigned, entries)

	result, err := client.GetAssignedEntries(context.Background())
	if err != nil {
		t.Fatalf("GetAssignedEntries() error: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("cached entries count = %d, want 1", len(result))
	}
}

func TestGetAssignedEntriesFetchPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(sampleAssignedData))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Nanosecond),
	)

	result, err := client.GetAssignedEntries(context.Background())
	if err != nil {
		t.Fatalf("GetAssignedEntries() error: %v", err)
	}
	if len(result) == 0 {
		t.Error("expected entries from fetch path")
	}
}

func TestGetAssignedEntriesFetchError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Nanosecond),
	)

	_, err := client.GetAssignedEntries(context.Background())
	if err == nil {
		t.Error("expected error for fetch failure in GetAssignedEntries")
	}
}
