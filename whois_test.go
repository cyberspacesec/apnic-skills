package apnic

import (
	"context"
	"testing"
	"time"
)

func TestQueryWhois(t *testing.T) {
	addr, cleanup := mockWhoisServer(t, sampleWhoisResponse)
	defer cleanup()

	client := NewClient(WithWhoisServer(addr))
	response, err := client.QueryWhois(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatalf("QueryWhois() error: %v", err)
	}
	if response == "" {
		t.Error("expected non-empty whois response")
	}
}

func TestQueryWhoisIP(t *testing.T) {
	addr, cleanup := mockWhoisServer(t, sampleWhoisResponse)
	defer cleanup()

	client := NewClient(WithWhoisServer(addr))
	info, err := client.QueryWhoisIP(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatalf("QueryWhoisIP() error: %v", err)
	}
	if info.Network != "1.1.1.0 - 1.1.1.255" {
		t.Errorf("network = %q, want 1.1.1.0 - 1.1.1.255", info.Network)
	}
	if info.Country != "AU" {
		t.Errorf("country = %q, want AU", info.Country)
	}
	if len(info.CIDR) != 1 || info.CIDR[0] != "1.1.1.0/24" {
		t.Errorf("cidr = %v, want [1.1.1.0/24]", info.CIDR)
	}
	if info.OrgName != "APNIC and Cloudflare DNS Resolver project" {
		t.Errorf("orgName = %q, want APNIC and Cloudflare DNS Resolver project", info.OrgName)
	}
	if info.Parent != "1.0.0.0 - 1.255.255.255" {
		t.Errorf("parent = %q, want 1.0.0.0 - 1.255.255.255", info.Parent)
	}
}

func TestQueryWhoisASN(t *testing.T) {
	addr, cleanup := mockWhoisServer(t, sampleWhoisResponse)
	defer cleanup()

	client := NewClient(WithWhoisServer(addr))
	info, err := client.QueryWhoisASN(context.Background(), 13335)
	if err != nil {
		t.Fatalf("QueryWhoisASN() error: %v", err)
	}
	if info.Country != "AU" {
		t.Errorf("country = %q, want AU", info.Country)
	}
}

func TestQueryWhoisWithFlags(t *testing.T) {
	addr, cleanup := mockWhoisServer(t, sampleWhoisResponse)
	defer cleanup()

	client := NewClient(WithWhoisServer(addr))
	response, err := client.QueryWhoisWithFlags(context.Background(), "1.1.1.1", "r")
	if err != nil {
		t.Fatalf("QueryWhoisWithFlags() error: %v", err)
	}
	if response == "" {
		t.Error("expected non-empty whois response")
	}
}

func TestQueryWhoisWithEmptyFlags(t *testing.T) {
	addr, cleanup := mockWhoisServer(t, sampleWhoisResponse)
	defer cleanup()

	client := NewClient(WithWhoisServer(addr))
	response, err := client.QueryWhoisWithFlags(context.Background(), "1.1.1.1", "")
	if err != nil {
		t.Fatalf("QueryWhoisWithFlags() with empty flags error: %v", err)
	}
	if response == "" {
		t.Error("expected non-empty whois response")
	}
}

func TestQueryWhoisWithContextDeadline(t *testing.T) {
	addr, cleanup := mockWhoisServer(t, sampleWhoisResponse)
	defer cleanup()

	client := NewClient(WithWhoisServer(addr))
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(30*time.Second))
	defer cancel()

	response, err := client.QueryWhois(ctx, "1.1.1.1")
	if err != nil {
		t.Fatalf("QueryWhois() with deadline error: %v", err)
	}
	if response == "" {
		t.Error("expected non-empty whois response")
	}
}

func TestParseWhoisResponse(t *testing.T) {
	info := ParseWhoisResponse(sampleWhoisResponse)
	if info.Network != "1.1.1.0 - 1.1.1.255" {
		t.Errorf("network = %q", info.Network)
	}
	if info.Country != "AU" {
		t.Errorf("country = %q", info.Country)
	}
	if len(info.CIDR) != 1 || info.CIDR[0] != "1.1.1.0/24" {
		t.Errorf("cidr = %v", info.CIDR)
	}
	if info.Created.IsZero() {
		t.Error("expected non-zero created date")
	}
	if info.LastUpdated.IsZero() {
		t.Error("expected non-zero lastUpdated date")
	}
}

func TestParseWhoisResponseEmpty(t *testing.T) {
	info := ParseWhoisResponse("")
	if info.Network != "" {
		t.Errorf("expected empty network, got %q", info.Network)
	}
}

func TestParseWhoisResponseComments(t *testing.T) {
	input := `% comment line
# another comment

inetnum:        10.0.0.0 - 10.0.0.255
country:        US
`
	info := ParseWhoisResponse(input)
	if info.Network != "10.0.0.0 - 10.0.0.255" {
		t.Errorf("network = %q", info.Network)
	}
	if info.Country != "US" {
		t.Errorf("country = %q", info.Country)
	}
}

func TestParseWhoisResponseOrgName(t *testing.T) {
	input := `inetnum:        1.1.1.0 - 1.1.1.255
descr:           First Descr
org-name:        Test Org
org:             Another Org
`
	info := ParseWhoisResponse(input)
	// descr is first and sets OrgName; org-name and org are skipped since OrgName is already set
	if info.OrgName != "First Descr" {
		t.Errorf("orgName = %q, want First Descr", info.OrgName)
	}
}

func TestParseWhoisResponseNoColon(t *testing.T) {
	input := `just a line with no colon
inetnum: 1.1.1.0 - 1.1.1.255
`
	info := ParseWhoisResponse(input)
	if info.Network != "1.1.1.0 - 1.1.1.255" {
		t.Errorf("network = %q", info.Network)
	}
}

func TestParseWhoisDateFormats(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"2011-08-10T23:12:35Z", true},
		{"2011-08-10T23:12:35+08:00", true},
		{"20110811", true},
		{"2011-08-11", true},
		{"invalid-date", false},
	}

	for _, tt := range tests {
		_, err := parseWhoisDate(tt.input)
		if tt.valid && err != nil {
			t.Errorf("parseWhoisDate(%q) unexpected error: %v", tt.input, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("parseWhoisDate(%q) expected error", tt.input)
		}
	}
}

func TestQueryWhoisConnectionFailed(t *testing.T) {
	client := NewClient(WithWhoisServer("127.0.0.1:1")) // port 1 should fail
	_, err := client.QueryWhois(context.Background(), "1.1.1.1")
	if err == nil {
		t.Error("expected error for failed connection")
	}
}

func TestQueryWhoisCancelledContext(t *testing.T) {
	client := NewClient(WithWhoisServer("127.0.0.1:1"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.QueryWhois(ctx, "1.1.1.1")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestQueryWhoisIPConnectionFailed(t *testing.T) {
	client := NewClient(WithWhoisServer("127.0.0.1:1"))
	_, err := client.QueryWhoisIP(context.Background(), "1.1.1.1")
	if err == nil {
		t.Error("expected error for failed connection")
	}
}

func TestQueryWhoisASNConnectionFailed(t *testing.T) {
	client := NewClient(WithWhoisServer("127.0.0.1:1"))
	_, err := client.QueryWhoisASN(context.Background(), 13335)
	if err == nil {
		t.Error("expected error for failed connection")
	}
}

func TestQueryWhoisWriteError(t *testing.T) {
	// Use a mock whois server and inject a dial function that returns a conn
	// with a simulated write error.
	addr, cleanup := mockWhoisServer(t, sampleWhoisResponse)
	defer cleanup()

	client := NewClient(
		WithWhoisServer(addr),
		withDialWhois(dialWithWriteError(addr)),
	)

	_, err := client.QueryWhois(context.Background(), "1.1.1.1")
	if err == nil {
		t.Error("expected error for write failure")
	}
}

func TestQueryWhoisReadError(t *testing.T) {
	// Use a mock whois server and inject a dial function that returns a conn
	// with a simulated read error.
	addr, cleanup := mockWhoisServer(t, sampleWhoisResponse)
	defer cleanup()

	client := NewClient(
		WithWhoisServer(addr),
		withDialWhois(dialWithReadError(addr)),
	)

	_, err := client.QueryWhois(context.Background(), "1.1.1.1")
	if err == nil {
		t.Error("expected error for read failure")
	}
}

// TestQueryWhois_RateLimitError covers the waitRateLimit-error branch of
// queryWhois: with a rate limiter and an already-cancelled context, the query
// fails before any dial is attempted.
func TestQueryWhois_RateLimitError(t *testing.T) {
	addr, cleanup := mockWhoisServer(t, sampleWhoisResponse)
	defer cleanup()
	client := NewClient(
		WithWhoisServer(addr),
		WithRateLimit(1.0),
		WithJitter(0, 0),
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.QueryWhois(ctx, "1.1.1.1"); err == nil {
		t.Error("expected waitRateLimit error from cancelled context")
	}
}
