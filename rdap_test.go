package apnic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
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
		w.Write([]byte(sampleRDAPSearchJSON))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
	)

	result, err := client.RDAPSearch(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatalf("RDAPSearch() error: %v", err)
	}
	if len(result.Results) != 1 {
		t.Errorf("results length = %d, want 1", len(result.Results))
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
