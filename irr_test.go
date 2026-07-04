package apnic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const sampleIRRDump = `# APNIC IRR dump (c) APNIC
# Conditions of use...
#

inetnum:        1.1.1.0 - 1.1.1.255
netname:        APNIC-LABS
descr:          APNIC and Cloudflare DNS Resolver project
descr:          second descr line
country:        AU
admin-c:        AIC3-AP
tech-c:         AIC3-AP
remarks:        leading remarks line
 + continuation folded without extra space
mnt-by:         APNIC-HM
last-modified:  2023-04-26T22:57:58Z
source:         APNIC

inetnum:        1.0.1.0 - 1.0.1.255
netname:        CN-NET
country:        CN
mnt-by:         MAINT-CNNIC
source:         APNIC
`

const sampleCurrentSerial = "16159398"

func TestIsIRRObjectType(t *testing.T) {
	for _, v := range IRRObjectTypes {
		if !isIRRObjectType(v) {
			t.Errorf("expected %q to be a valid IRR object type", v)
		}
	}
	if isIRRObjectType("bogus") {
		t.Error("expected bogus to be invalid")
	}
	if len(IRRObjectTypes) != 19 {
		t.Errorf("IRRObjectTypes count = %d, want 19", len(IRRObjectTypes))
	}
}

func TestParseIRRDatabase(t *testing.T) {
	db, err := parseIRRDatabase("inetnum", sampleIRRDump)
	if err != nil {
		t.Fatalf("parseIRRDatabase() error: %v", err)
	}
	if len(db.Objects) != 2 {
		t.Fatalf("objects = %d, want 2", len(db.Objects))
	}
	if db.Objects[0].Type != "inetnum" {
		t.Errorf("type = %q, want inetnum", db.Objects[0].Type)
	}
	if db.Objects[0].PrimaryKey != "1.1.1.0 - 1.1.1.255" {
		t.Errorf("pk = %q", db.Objects[0].PrimaryKey)
	}
	desc := db.Objects[0].Attributes["descr"]
	if len(desc) != 2 || desc[0] != "APNIC and Cloudflare DNS Resolver project" {
		t.Errorf("descr = %v", desc)
	}
	// Continuation line (leading whitespace, '+' suppresses the extra space that
	// a plain continuation would add; the content after '+' is preserved verbatim).
	remarks := db.Objects[0].Attributes["remarks"]
	if len(remarks) != 2 || remarks[1] != " continuation folded without extra space" {
		t.Errorf("remarks = %v", remarks)
	}
	if db.Objects[1].Attributes["country"][0] != "CN" {
		t.Errorf("second country = %v", db.Objects[1].Attributes["country"])
	}
}

func TestParseIRRDatabase_EmptyAndComments(t *testing.T) {
	db, err := parseIRRDatabase("route", "# only comments\n\n# more\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Objects) != 0 {
		t.Errorf("expected 0 objects, got %d", len(db.Objects))
	}
}

func TestParseIRRDatabase_DefensiveBranches(t *testing.T) {
	// Continuation line before any active attribute (cur==nil) is ignored;
	// a line without a colon is skipped.
	data := "# header\n\n   orphan continuation\ninetnum: 1.1.1.0 - 1.1.1.255\nno colon here\ncountry: AU\nsource: APNIC\n"
	db, err := parseIRRDatabase("inetnum", data)
	if err != nil {
		t.Fatalf("parseIRRDatabase() error: %v", err)
	}
	if len(db.Objects) != 1 {
		t.Fatalf("objects = %d, want 1", len(db.Objects))
	}
	if db.Objects[0].Attributes["country"][0] != "AU" {
		t.Errorf("country = %v", db.Objects[0].Attributes["country"])
	}
}

// TestParseIRRDatabase_ContinuationNoPlus covers the continuation branch where
// the value does not start with '+' (the else branch prepends a space).
func TestParseIRRDatabase_ContinuationNoPlus(t *testing.T) {
	// "inetnum: 1.1.1.0 - 1.1.1.255" then a continuation "  .au" (no '+') and a
	// '+' continuation "  +extra" (leading space + plus).
	data := "inetnum: 1.1.1.0 - 1.1.1.255\n  .au\n  +extra\nsource: APNIC\n"
	db, err := parseIRRDatabase("inetnum", data)
	if err != nil {
		t.Fatalf("parseIRRDatabase() error: %v", err)
	}
	vals := db.Objects[0].Attributes["inetnum"]
	// Expect base, " .au" (space-prepended), "extra" ('+' stripped).
	if len(vals) != 3 {
		t.Fatalf("inetnum attrs = %v, want 3", vals)
	}
	if vals[1] != " .au" {
		t.Errorf("continuation[1] = %q, want %q", vals[1], " .au")
	}
	if vals[2] != "extra" {
		t.Errorf("continuation[2] = %q, want %q", vals[2], "extra")
	}
}

// TestParseIRRDatabase_ScannerErr covers the scanner.Err branch via a line
// exceeding the 4MB buffer.
func TestParseIRRDatabase_ScannerErr(t *testing.T) {
	huge := strings.Repeat("x", 5*1024*1024) + "\n"
	if _, err := parseIRRDatabase("inetnum", huge); err == nil {
		t.Error("expected scanner error on >4MB line")
	}
}

func TestFetchIRRDatabase_InvalidType(t *testing.T) {
	client := NewClient()
	_, err := client.FetchIRRDatabase(context.Background(), "bogus")
	if err == nil {
		t.Fatal("expected error for invalid IRR type")
	}
}

func TestFetchIRRDatabase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The dump URL ends in .gz; fetchText decompresses by suffix.
		if strings.HasSuffix(r.URL.Path, "APNIC.CURRENTSERIAL") {
			w.Write([]byte(sampleCurrentSerial))
			return
		}
		serveDated(w, r, sampleIRRDump) // .gz-suffixed path served gzip-compressed
	}))
	defer srv.Close()
	client := NewClient(WithHTTPClient(srv.Client()), WithFTPBaseURL(srv.URL+"/"), WithJitter(0, 0))

	db, err := client.FetchIRRDatabase(context.Background(), "inetnum")
	if err != nil {
		t.Fatalf("FetchIRRDatabase() error: %v", err)
	}
	if len(db.Objects) != 2 {
		t.Errorf("objects = %d, want 2", len(db.Objects))
	}
	if db.Type != "inetnum" {
		t.Errorf("type = %q", db.Type)
	}

	serial, err := client.FetchIRRCurrentSerial(context.Background())
	if err != nil {
		t.Fatalf("FetchIRRCurrentSerial() error: %v", err)
	}
	if serial != 16159398 {
		t.Errorf("serial = %d, want 16159398", serial)
	}
}

func TestFetchIRRDatabaseHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	client := NewClient(WithHTTPClient(srv.Client()), WithFTPBaseURL(srv.URL+"/"), WithJitter(0, 0))
	if _, err := client.FetchIRRDatabase(context.Background(), "inetnum"); err == nil {
		t.Error("expected error on HTTP 500")
	}
	if _, err := client.FetchIRRCurrentSerial(context.Background()); err == nil {
		t.Error("expected error on HTTP 500 for serial")
	}
}

func TestFetchIRRCurrentSerialBadData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not a number"))
	}))
	defer srv.Close()
	client := NewClient(WithHTTPClient(srv.Client()), WithFTPBaseURL(srv.URL+"/"), WithJitter(0, 0))
	if _, err := client.FetchIRRCurrentSerial(context.Background()); err == nil {
		t.Error("expected error for non-numeric serial")
	}
}

func TestGetIRRDatabaseWithCache(t *testing.T) {
	client := NewClient(WithCacheTTL(1 * time.Hour))
	// Manually seed cache to verify the Get path returns cached data.
	db := &IRRDatabase{Type: "route", Objects: []IRRObject{{Type: "route", PrimaryKey: "1.0.0.0/24"}}}
	client.cache.set(cacheKeyIRR("route"), db)

	got, err := client.GetIRRDatabase(context.Background(), "route")
	if err != nil {
		t.Fatalf("GetIRRDatabase() error: %v", err)
	}
	if len(got.Objects) != 1 {
		t.Errorf("objects = %d, want 1", len(got.Objects))
	}
}

func TestGetIRRDatabaseFetchPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveDated(w, r, sampleIRRDump)
	}))
	defer srv.Close()
	client := NewClient(
		WithHTTPClient(srv.Client()),
		WithFTPBaseURL(srv.URL+"/"),
		WithCacheTTL(0), // force fetch path
		WithJitter(0, 0),
	)
	got, err := client.GetIRRDatabase(context.Background(), "inetnum")
	if err != nil {
		t.Fatalf("GetIRRDatabase() error: %v", err)
	}
	if len(got.Objects) != 2 {
		t.Errorf("objects = %d, want 2", len(got.Objects))
	}
}

// TestGetIRRDatabaseFetchError covers the cache-miss + fetch-error branch of
// GetIRRDatabase (the FetchIRRDatabase error propagates).
func TestGetIRRDatabaseFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	client := NewClient(
		WithHTTPClient(srv.Client()),
		WithFTPBaseURL(srv.URL+"/"),
		WithCacheTTL(0),
		WithJitter(0, 0),
		WithMaxConcurrentDownloads(0),
	)
	if _, err := client.GetIRRDatabase(context.Background(), "inetnum"); err == nil {
		t.Error("expected error from GetIRRDatabase when fetch fails")
	}
}
