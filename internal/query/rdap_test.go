package query

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRDAPLookupIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ip/1.1.1.1" {
			w.Header().Set("Content-Type", "application/rdap+json")
			w.Write([]byte(sampleRDAPNetworkJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	network, err := client.RDAPLookupIP(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatalf("RDAPLookupIP() error: %v", err)
	}
	if network.Name != "APNIC-LABS" {
		t.Errorf("name = %q, want APNIC-LABS", network.Name)
	}
	if network.Country != "AU" {
		t.Errorf("country = %q, want AU", network.Country)
	}
	if network.IPVersion != "v4" {
		t.Errorf("ipVersion = %q, want v4", network.IPVersion)
	}
	if network.Handle != "1.1.1.0 - 1.1.1.255" {
		t.Errorf("handle = %q, want 1.1.1.0 - 1.1.1.255", network.Handle)
	}
	if len(network.Status) != 1 || network.Status[0] != "active" {
		t.Errorf("status = %v, want [active]", network.Status)
	}
	if len(network.CIDR0CIDRs) != 1 {
		t.Errorf("cidr0_cidrs length = %d, want 1", len(network.CIDR0CIDRs))
	}
	if len(network.Entities) != 1 {
		t.Errorf("entities length = %d, want 1", len(network.Entities))
	}
	if len(network.Events) != 2 {
		t.Errorf("events length = %d, want 2", len(network.Events))
	}
}

func TestRDAPLookupCIDR(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write([]byte(sampleRDAPNetworkJSON))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	network, err := client.RDAPLookupCIDR(context.Background(), "1.1.1.0/24")
	if err != nil {
		t.Fatalf("RDAPLookupCIDR() error: %v", err)
	}
	if network.Name != "APNIC-LABS" {
		t.Errorf("name = %q, want APNIC-LABS", network.Name)
	}
}

func TestRDAPLookupASN(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write([]byte(sampleRDAPAutnumJSON))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	autnum, err := client.RDAPLookupASN(context.Background(), 13335)
	if err != nil {
		t.Fatalf("RDAPLookupASN() error: %v", err)
	}
	if autnum.Name != "CLOUDFLARE" {
		t.Errorf("name = %q, want CLOUDFLARE", autnum.Name)
	}
	if autnum.StartAutnum != 13335 {
		t.Errorf("startAutnum = %d, want 13335", autnum.StartAutnum)
	}
	if autnum.EndAutnum != 13335 {
		t.Errorf("endAutnum = %d, want 13335", autnum.EndAutnum)
	}
	if autnum.Country != "AU" {
		t.Errorf("country = %q, want AU", autnum.Country)
	}
}

func TestRDAPLookupDomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write([]byte(sampleRDAPDomainJSON))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	domain, err := client.RDAPLookupDomain(context.Background(), "1.0.0.1.in-addr.arpa")
	if err != nil {
		t.Fatalf("RDAPLookupDomain() error: %v", err)
	}
	if domain.LDHName != "1.0.0.1.in-addr.arpa" {
		t.Errorf("ldhName = %q, want 1.0.0.1.in-addr.arpa", domain.LDHName)
	}
	if len(domain.Nameservers) != 1 {
		t.Errorf("nameservers length = %d, want 1", len(domain.Nameservers))
	}
}

func TestRDAPLookupEntity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write([]byte(sampleRDAPEntityJSON))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	entity, err := client.RDAPLookupEntity(context.Background(), "AIC3-AP")
	if err != nil {
		t.Fatalf("RDAPLookupEntity() error: %v", err)
	}
	if entity.Handle != "AIC3-AP" {
		t.Errorf("handle = %q, want AIC3-AP", entity.Handle)
	}
	if len(entity.Roles) != 2 {
		t.Errorf("roles length = %d, want 2", len(entity.Roles))
	}
	if len(entity.VcardArray) != 2 {
		t.Errorf("vcardArray length = %d, want 2", len(entity.VcardArray))
	}
}

func TestRDAPSearch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		if !strings.Contains(r.URL.Path, "/entities") {
			t.Errorf("expected /entities path, got %s", r.URL.Path)
		}
		if r.URL.Query().Get("fn") != "*CLOUD*" {
			t.Errorf("expected fn=*CLOUD*, got %q", r.URL.Query().Get("fn"))
		}
		w.Write([]byte(sampleRDAPSearchJSON))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	result, err := client.RDAPSearch(context.Background(), "*CLOUD*")
	if err != nil {
		t.Fatalf("RDAPSearch() error: %v", err)
	}
	if len(result.EntitySearchResults) != 2 {
		t.Errorf("entitySearchResults length = %d, want 2", len(result.EntitySearchResults))
	}
}

func TestRDAPSearchEntities(t *testing.T) {
	var requestedField, requestedValue string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		q := r.URL.Query()
		requestedField = ""
		requestedValue = ""
		if v := q.Get("fn"); v != "" {
			requestedField = "fn"
			requestedValue = v
		}
		if v := q.Get("handle"); v != "" {
			requestedField = "handle"
			requestedValue = v
		}
		w.Write([]byte(sampleRDAPSearchJSON))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	// fn search
	result, err := client.RDAPSearchEntities(context.Background(), "fn", "*CLOUD*")
	if err != nil {
		t.Fatalf("RDAPSearchEntities(fn) error: %v", err)
	}
	if len(result.EntitySearchResults) != 2 {
		t.Errorf("fn search results = %d, want 2", len(result.EntitySearchResults))
	}
	if requestedField != "fn" || requestedValue != "*CLOUD*" {
		t.Errorf("fn search request = %s=%s, want fn=*CLOUD*", requestedField, requestedValue)
	}

	// handle search
	_, err = client.RDAPSearchEntities(context.Background(), "handle", "ORG-ARAD1-AP")
	if err != nil {
		t.Fatalf("RDAPSearchEntities(handle) error: %v", err)
	}
	if requestedField != "handle" || requestedValue != "ORG-ARAD1-AP" {
		t.Errorf("handle search request = %s=%s, want handle=ORG-ARAD1-AP", requestedField, requestedValue)
	}
}

func TestRDAPSearchEntitiesInvalidField(t *testing.T) {
	client := NewClient()
	_, err := client.RDAPSearchEntities(context.Background(), "bogus", "x")
	if err == nil {
		t.Error("expected error for unsupported search field")
	}
}

func TestRDAPSearchEntitiesEmptyQuery(t *testing.T) {
	client := NewClient()
	_, err := client.RDAPSearchEntities(context.Background(), "fn", "")
	if err == nil {
		t.Error("expected error for empty search query")
	}
}

func TestRDAPLookupIPAt(t *testing.T) {
	var capturedDate string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		capturedDate = r.URL.Query().Get("date")
		w.Write([]byte(sampleRDAPNetworkJSON))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	// Point-in-time query should attach a date parameter.
	date := time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC)
	_, err := client.RDAPLookupIPAt(context.Background(), "1.1.1.1", date)
	if err != nil {
		t.Fatalf("RDAPLookupIPAt() error: %v", err)
	}
	if capturedDate != "2020-06-01T00:00:00Z" {
		t.Errorf("date param = %q, want 2020-06-01T00:00:00Z", capturedDate)
	}
}

func TestRDAPLookupIPAtZeroDateIsLive(t *testing.T) {
	var capturedDate string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		capturedDate = r.URL.Query().Get("date")
		w.Write([]byte(sampleRDAPNetworkJSON))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	// A zero date with no client default should produce a live query (no date param).
	_, err := client.RDAPLookupIPAt(context.Background(), "1.1.1.1", time.Time{})
	if err != nil {
		t.Fatalf("RDAPLookupIPAt() error: %v", err)
	}
	if capturedDate != "" {
		t.Errorf("expected no date param for live query, got %q", capturedDate)
	}
}

func TestWithRDAPDateClientDefault(t *testing.T) {
	var capturedDate string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		capturedDate = r.URL.Query().Get("date")
		w.Write([]byte(sampleRDAPNetworkJSON))
	}))
	defer server.Close()

	// Client-level default date applies to all lookups.
	defaultDate := time.Date(2019, 1, 15, 12, 30, 0, 0, time.UTC)
	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
		WithRDAPDate(defaultDate),
	)

	_, err := client.RDAPLookupIP(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatalf("RDAPLookupIP() error: %v", err)
	}
	if capturedDate != "2019-01-15T12:30:00Z" {
		t.Errorf("client default date param = %q, want 2019-01-15T12:30:00Z", capturedDate)
	}

	// A per-call date overrides the client default.
	capturedDate = ""
	override := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)
	_, err = client.RDAPLookupASNAt(context.Background(), 13335, override)
	if err != nil {
		t.Fatalf("RDAPLookupASNAt() error: %v", err)
	}
	if capturedDate != "2021-03-04T05:06:07Z" {
		t.Errorf("per-call override date param = %q, want 2021-03-04T05:06:07Z", capturedDate)
	}
}

func TestRDAPLookupAtVariants(t *testing.T) {
	// All *At variants exercise the point-in-time path; verify they return data.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write([]byte(sampleRDAPNetworkJSON))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)
	date := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	if _, err := client.RDAPLookupCIDRAt(context.Background(), "1.1.1.0/24", date); err != nil {
		t.Errorf("RDAPLookupCIDRAt() error: %v", err)
	}
}

func TestRDAPNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(sampleRDAPNotFoundJSON))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	_, err := client.RDAPLookupIP(context.Background(), "0.0.0.0")
	if err == nil {
		t.Error("expected error for not found")
	}
}

func TestRDAPNotFoundNoJSON(t *testing.T) {
	// Test 404 response without valid RDAP error JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	_, err := client.RDAPLookupIP(context.Background(), "0.0.0.0")
	if err == nil {
		t.Error("expected error for not found")
	}
}

func TestRDAPServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	_, err := client.RDAPLookupIP(context.Background(), "1.1.1.1")
	if err == nil {
		t.Error("expected error for server error")
	}
}

func TestRDAPServerErrorWithJSON(t *testing.T) {
	// Test non-200 response with RDAP error JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errorCode":403,"title":"Forbidden","description":["Access denied"]}`))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	_, err := client.RDAPLookupIP(context.Background(), "1.1.1.1")
	if err == nil {
		t.Error("expected error for forbidden")
	}
}

func TestRDAPServerErrorWithoutJSON(t *testing.T) {
	// Test non-200 response without RDAP error JSON (no title)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	_, err := client.RDAPLookupIP(context.Background(), "1.1.1.1")
	if err == nil {
		t.Error("expected error for bad gateway")
	}
}

func TestRDAPInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	_, err := client.RDAPLookupIP(context.Background(), "1.1.1.1")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestRDAPCancelledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write([]byte(sampleRDAPNetworkJSON))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.RDAPLookupIP(ctx, "1.1.1.1")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestRDAPLookupCIDRError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(sampleRDAPNotFoundJSON))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	_, err := client.RDAPLookupCIDR(context.Background(), "0.0.0.0/0")
	if err == nil {
		t.Error("expected error for not found")
	}
}

func TestRDAPLookupASNError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(sampleRDAPNotFoundJSON))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	_, err := client.RDAPLookupASN(context.Background(), 0)
	if err == nil {
		t.Error("expected error for not found")
	}
}

func TestRDAPLookupDomainError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(sampleRDAPNotFoundJSON))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	_, err := client.RDAPLookupDomain(context.Background(), "nonexistent.arpa")
	if err == nil {
		t.Error("expected error for not found")
	}
}

func TestRDAPLookupEntityError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(sampleRDAPNotFoundJSON))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	_, err := client.RDAPLookupEntity(context.Background(), "NONEXISTENT")
	if err == nil {
		t.Error("expected error for not found")
	}
}

func TestRDAPSearchError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(sampleRDAPNotFoundJSON))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	_, err := client.RDAPSearch(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for not found")
	}
}

func TestRDAPRequestCreationError(t *testing.T) {
	client := NewClient(
		WithRDAPBaseURL("http://[::1]:%invalid/"),
	)

	_, err := client.RDAPLookupIP(context.Background(), "1.1.1.1")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestRDAPReadError(t *testing.T) {
	// Use a custom RoundTripper that returns a body that errors on read
	client := NewClient(
		WithHTTPClient(&http.Client{Transport: errorRoundTripper{}}),
		WithRDAPBaseURL("http://example.com"),
	)

	_, err := client.RDAPLookupIP(context.Background(), "1.1.1.1")
	if err == nil {
		t.Error("expected error for read failure")
	}
}

func TestRDAPHelp(t *testing.T) {
	client, server := newTestClient(combinedHandler())
	defer server.Close()
	h, err := client.RDAPHelp(context.Background())
	if err != nil {
		t.Fatalf("RDAPHelp() error: %v", err)
	}
	if h.Port43 != "whois.apnic.net" {
		t.Errorf("port43 = %q, want whois.apnic.net", h.Port43)
	}
	if len(h.Conformance) == 0 {
		t.Error("expected non-empty conformance")
	}
	found := false
	for _, c := range h.Conformance {
		if c == "history_version_0" {
			found = true
		}
	}
	if !found {
		t.Error("expected history_version_0 in conformance")
	}
	if len(h.Notices) != 2 {
		t.Errorf("notices = %d, want 2", len(h.Notices))
	}
}

func TestRDAPHelp_NotFound(t *testing.T) {
	// Server returns 404 for /help when not routed; use a stats-only handler.
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"errorCode":404,"title":"Not Found"}`))
	})
	defer server.Close()
	if _, err := client.RDAPHelp(context.Background()); err == nil {
		t.Error("expected error for /help 404")
	}
}

func TestRDAPSearchDomains(t *testing.T) {
	client, server := newTestClient(combinedHandler())
	defer server.Close()
	r, err := client.RDAPSearchDomains(context.Background(), "1.in-addr.arpa")
	if err != nil {
		t.Fatalf("RDAPSearchDomains() error: %v", err)
	}
	if len(r.DomainSearchResults) != 2 {
		t.Errorf("results = %d, want 2", len(r.DomainSearchResults))
	}
	if r.DomainSearchResults[0].Handle != "1.in-addr.arpa" {
		t.Errorf("first handle = %q, want 1.in-addr.arpa", r.DomainSearchResults[0].Handle)
	}
}

func TestRDAPSearchDomains_EmptyQuery(t *testing.T) {
	client, server := newTestClient(combinedHandler())
	defer server.Close()
	if _, err := client.RDAPSearchDomains(context.Background(), ""); err == nil {
		t.Error("expected error for empty domain search query")
	}
}

// TestRDAPSearchDomains_HTTPError covers the doRDAPRequestAt-error branch.
func TestRDAPSearchDomains_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	client := NewClient(WithRDAPBaseURL(srv.URL), WithJitter(0, 0), WithCacheTTL(0))
	if _, err := client.RDAPSearchDomains(context.Background(), "1.in-addr.arpa"); err == nil {
		t.Error("expected error on HTTP 500 for domain search")
	}
}
