package apnic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchHistoricalDelegatedInvalidDate(t *testing.T) {
	client := NewClient()
	_, err := client.FetchHistoricalDelegated(context.Background(), "invalid")
	if err == nil {
		t.Error("expected error for invalid date format")
	}
}

func TestFetchHistoricalExtendedInvalidDate(t *testing.T) {
	client := NewClient()
	_, err := client.FetchHistoricalExtended(context.Background(), "2026")
	if err == nil {
		t.Error("expected error for invalid date format")
	}
}

func TestFetchHistoricalAssignedInvalidDate(t *testing.T) {
	client := NewClient()
	_, err := client.FetchHistoricalAssigned(context.Background(), "abc")
	if err == nil {
		t.Error("expected error for invalid date")
	}
}

func TestFetchHistoricalLegacyInvalidDate(t *testing.T) {
	client := NewClient()
	_, err := client.FetchHistoricalLegacy(context.Background(), "xyz")
	if err == nil {
		t.Error("expected error for invalid date")
	}
}

func TestFetchHistoricalDelegated(t *testing.T) {
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

	result, err := client.FetchHistoricalDelegated(context.Background(), "20260627")
	if err != nil {
		t.Fatalf("FetchHistoricalDelegated() error: %v", err)
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
}

func TestFetchHistoricalExtended(t *testing.T) {
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

	result, err := client.FetchHistoricalExtended(context.Background(), "20260627")
	if err != nil {
		t.Fatalf("FetchHistoricalExtended() error: %v", err)
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
}

func TestFetchHistoricalAssigned(t *testing.T) {
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

	result, err := client.FetchHistoricalAssigned(context.Background(), "20260627")
	if err != nil {
		t.Fatalf("FetchHistoricalAssigned() error: %v", err)
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
}

func TestFetchHistoricalLegacy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(sampleLegacyData))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	result, err := client.FetchHistoricalLegacy(context.Background(), "20260627")
	if err != nil {
		t.Fatalf("FetchHistoricalLegacy() error: %v", err)
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
}

func TestFetchDelegatedByYearInvalid(t *testing.T) {
	client := NewClient()
	_, err := client.FetchDelegatedByYear(context.Background(), 2000)
	if err == nil {
		t.Error("expected error for invalid year")
	}
}

func TestFetchDelegatedByYear(t *testing.T) {
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

	result, err := client.FetchDelegatedByYear(context.Background(), 2026)
	if err != nil {
		t.Fatalf("FetchDelegatedByYear() error: %v", err)
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
}

func TestFetchDelegatedByYearHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	_, err := client.FetchDelegatedByYear(context.Background(), 2026)
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}

func TestFetchExtendedByYearInvalid(t *testing.T) {
	client := NewClient()
	_, err := client.FetchExtendedByYear(context.Background(), 1999)
	if err == nil {
		t.Error("expected error for invalid year")
	}
}

func TestFetchExtendedByYear(t *testing.T) {
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

	result, err := client.FetchExtendedByYear(context.Background(), 2026)
	if err != nil {
		t.Fatalf("FetchExtendedByYear() error: %v", err)
	}
	if len(result.Entries) == 0 {
		t.Error("expected entries")
	}
}

func TestFetchExtendedByYearHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithStatsBaseURL(server.URL+"/"),
		WithCacheTTL(1*time.Hour),
	)

	_, err := client.FetchExtendedByYear(context.Background(), 2026)
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}

func TestListAvailableYears(t *testing.T) {
	years := ListAvailableYears()
	if len(years) == 0 {
		t.Error("expected non-empty years list")
	}
	if years[0] != 2001 {
		t.Errorf("first year = %d, want 2001", years[0])
	}
}
