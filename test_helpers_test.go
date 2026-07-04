package apnic

import (
	"compress/gzip"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// init disables request jitter for the whole test binary so the suite runs fast.
// stealth_test.go re-enables it locally via t.Setenv where real jitter is needed.
func init() {
	_ = os.Setenv("APNIC_NO_JITTER", "1")
}

// md5Hash computes the MD5 hash of a string.
func md5Hash(data string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(data)))
}

// gzipBytes gzip-compresses the given data, for serving .gz responses in tests.
func gzipBytes(data string) []byte {
	var buf strings.Builder
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(data))
	zw.Close()
	return []byte(buf.String())
}

// serveDated writes sample as either gzip-compressed (when the request URL ends
// in .gz, matching APNIC's dated-file layout) or plain text (for latest files).
// datePrefix sets the Content-Type appropriately.
func serveDated(w http.ResponseWriter, r *http.Request, sample string) {
	if strings.HasSuffix(r.URL.Path, ".gz") {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(gzipBytes(sample))
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(sample))
}

// stringReader creates an io.Reader from a string.
func stringReader(s string) io.Reader {
	return strings.NewReader(s)
}

// errorReader is an io.Reader that always returns an error.
type errorReader struct{}

func (errorReader) Read(_ []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

// errorRoundTripper is an http.RoundTripper that returns a response with
// a body that errors on read. This triggers io.Copy / io.ReadAll errors.
type errorRoundTripper struct{}

func (errorRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(errorReader{}),
	}, nil
}

// errorConn is a net.Conn wrapper that can inject write and read errors.
type errorConn struct {
	net.Conn
	writeErr error
	readErr  error
}

func (c *errorConn) Write(b []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.Conn.Write(b)
}

func (c *errorConn) Read(b []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.Conn.Read(b)
}

// withDialWhois sets a custom dial function for whois connections (for testing).
func withDialWhois(fn dialFunc) Option {
	return func(c *Client) {
		c.dialWhois = fn
	}
}

// dialWithWriteError creates a dial function that connects to the given address
// but wraps the connection with a write error.
func dialWithWriteError(addr string) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &errorConn{Conn: conn, writeErr: fmt.Errorf("simulated write error")}, nil
	}
}

// dialWithReadError creates a dial function that connects to the given address
// but wraps the connection with a read error.
func dialWithReadError(addr string) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &errorConn{Conn: conn, readErr: fmt.Errorf("simulated read error")}, nil
	}
}

// newTestClient creates a Client with a mock HTTP server that intercepts
// both stats (FTP) and RDAP requests. Jitter/stealth pacing is disabled to keep
// tests fast; stealth headers are validated separately in stealth_test.go.
func newTestClient(handler http.HandlerFunc) (*Client, *httptest.Server) {
	server := httptest.NewServer(handler)
	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
		WithCacheTTL(1*time.Hour),
		WithJitter(0, 0),
	)
	return client, server
}

// mockWhoisServer starts a TCP server that mimics a Whois server.
func mockWhoisServer(t *testing.T, response string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 1024)
				conn.Read(buf)
				conn.Write([]byte(response))
			}()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// allStatsHandler returns an HTTP handler that serves all types of APNIC data
// based on URL path patterns. This allows us to test Fetch* methods without
// hitting real servers. Dated (.gz) requests are served gzip-compressed.
func allStatsHandler() http.HandlerFunc {
	// pickSample selects the sample payload for a given path.
	pickSample := func(path string) (string, string) {
		switch {
		case strings.Contains(path, "delegated-extended"):
			return sampleExtendedData, "text/plain"
		case strings.Contains(path, "delegated-ipv6-assigned"):
			return sampleIPv6AssignedData, "text/plain"
		case strings.Contains(path, "assigned"):
			return sampleAssignedData, "text/plain"
		case strings.Contains(path, "legacy"):
			return sampleLegacyData, "text/plain"
		case strings.Contains(path, "delegated"):
			return sampleDelegatedData, "text/plain"
		case strings.Contains(path, "transfers"):
			return sampleTransfersJSON, "application/json"
		case strings.Contains(path, "changes"):
			return sampleChangesData, "application/json"
		default:
			return sampleRDAPNotFoundJSON, "application/rdap+json"
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		sample, contentType := pickSample(path)
		if strings.HasSuffix(path, ".gz") {
			w.Header().Set("Content-Type", "application/gzip")
			w.Write(gzipBytes(sample))
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Write([]byte(sample))
	}
}

// rdapHandler returns an HTTP handler for RDAP requests.
func rdapHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		path := r.URL.Path

		switch {
		case strings.Contains(path, "/ip/"):
			w.Write([]byte(sampleRDAPNetworkJSON))
		case strings.Contains(path, "/autnum/"):
			w.Write([]byte(sampleRDAPAutnumJSON))
		case strings.Contains(path, "/domain/"):
			w.Write([]byte(sampleRDAPDomainJSON))
		case strings.Contains(path, "/entity/"):
			w.Write([]byte(sampleRDAPEntityJSON))
		case strings.Contains(path, "/entities"):
			w.Write([]byte(sampleRDAPSearchJSON))
		case strings.Contains(path, "/domains"):
			w.Write([]byte(sampleRDAPDomainsSearchJSON))
		case strings.HasSuffix(path, "/help"):
			w.Write([]byte(sampleRDAPHelpJSON))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(sampleRDAPNotFoundJSON))
		}
	}
}

// combinedHandler returns an HTTP handler that routes stats and RDAP requests.
func combinedHandler() http.HandlerFunc {
	stats := allStatsHandler()
	rdap := rdapHandler()

	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasPrefix(path, "/ip/") ||
			strings.HasPrefix(path, "/autnum/") ||
			strings.HasPrefix(path, "/domain/") ||
			strings.HasPrefix(path, "/domains") ||
			strings.HasPrefix(path, "/entity/") ||
			strings.HasPrefix(path, "/entities") ||
			strings.HasSuffix(path, "/help") {
			rdap(w, r)
		} else {
			stats(w, r)
		}
	}
}

// Sample data for tests
const sampleDelegatedData = `2|apnic|20260627|5|19850701|20260626|+1000
apnic|*|asn|*|100|summary
apnic|*|ipv4|*|200|summary
apnic|*|ipv6|*|50|summary
apnic|JP|asn|173|1|20020801|allocated
apnic|AU|asn|1221|1|20000131|allocated
apnic|AU|ipv4|1.0.0.0|256|20110811|assigned
apnic|CN|ipv4|1.0.1.0|256|20110414|allocated
apnic|CN|ipv4|1.0.2.0|512|20110414|allocated
apnic|AU|ipv4|1.0.4.0|1024|20110412|allocated
apnic|JP|ipv6|2001:240::|32|20020801|allocated
apnic|AU|ipv6|2001:200::|32|20000131|allocated
`

const sampleExtendedData = `2.3|apnic|20260627|5|19850701|20260626|+1000
apnic|*|asn|*|100|summary
apnic|*|ipv4|*|200|summary
apnic|*|ipv6|*|50|summary
apnic|AU|ipv4|1.0.0.0|256|20110811|assigned|A91872ED
apnic|CN|ipv4|1.0.1.0|256|20110414|allocated|A92E1062
apnic|CN|ipv4|1.0.2.0|512|20110414|allocated|A92E1062
apnic|JP|ipv6|2001:240::|32|20020801|allocated|A92D9378
apnic|AU|asn|1221|1|20000131|allocated|A91872ED
`

const sampleAssignedData = `1|apnic|20260627|5|19850701|20260626|+1000
apnic|*|ipv4|*|100|summary
apnic|*|ipv6|*|50|summary
apnic|ae|ipv4||4||assigned||1
apnic|ae|ipv4||16||assigned||3
apnic|ae|ipv4||256||assigned||12
apnic|jp|ipv6||48||assigned||5
`

const sampleIPv6AssignedData = `2|apnic|20260629|7621|20020116|20260626|+1000
apnic|*|ipv6|*|7621|summary
apnic|HK|ipv6|2001:7fa:0:1::|64|20020116
apnic|KR|ipv6|2001:7fa:0:2::|64|20020117
apnic|JP|ipv6|2001:7fa:0:3::|64|20020226
apnic|TW|ipv6|2001:7fa:1::|48|20021023
`

const sampleLegacyData = `1|apnic|20260627|3|19850701|20260626|+1000
apnic|*|ipv4|*|100|summary
apnic||ipv4|128.134.0.0|65536|20040401|allocated
apnic||ipv4|128.184.0.0|65536|20040401|allocated
apnic||ipv4|128.250.0.0|65536|20040401|allocated
apnic||ipv6|2001:db8::|32|20040401|allocated
apnic||asn|237|1|20020801|allocated
`

const sampleTransfersJSON = `{
  "version": {
    "producer": "APNIC",
    "production_date": "2026-06-25T18:00:04Z",
    "remarks": [],
    "UTC_offset": 10,
    "stats_version": "4.0",
    "records_interval": {
      "start_date": "2010-04-07T00:29:32Z",
      "end_date": "2026-06-25T18:00:04Z"
    }
  },
  "transfers": [
    {
      "transfer_date": "2020-01-15T00:00:00Z",
      "type": "RESOURCE_TRANSFER",
      "source_rir": "APNIC",
      "recipient_rir": "APNIC",
      "source_organization": {"name": "Org A", "country_code": "AU"},
      "recipient_organization": {"name": "Org B", "country_code": "CN"},
      "ip4nets": {"transfer_set": [{"start_address": "1.2.3.0", "end_address": "1.2.3.255"}]},
      "ip6nets": null,
      "asns": null
    },
    {
      "transfer_date": "2021-03-20T00:00:00Z",
      "type": "INTER_RIR_TRANSFER",
      "source_rir": "ARIN",
      "recipient_rir": "APNIC",
      "source_organization": {"name": "Org C", "country_code": "US"},
      "recipient_organization": {"name": "Org D", "country_code": "JP"},
      "ip4nets": null,
      "ip6nets": {"transfer_set": [{"start_address": "2001:db8::", "end_address": "2001:db8:0:ffff:ffff:ffff:ffff:ffff"}]},
      "asns": {"transfer_set": [{"start_as_number": 64512, "end_as_number": 64520}]}
    }
  ]
}`

const sampleTransfersAll = `######################################################################
#
# CONDITIONS OF USE
#
######################################################################
resource_type|resource|from_organisation|from_economy|from_rir|previous_delegation_date|to_organisation|to_economy|to_rir|transfer_date|transfer_type
asn|45745|Gambit Group Pty Ltd|AU|APNIC|20090417|Bathurst One Pty Limited|AU|APNIC|20120620|M&A
ipv4|1.2.3.0|Org A|AU|APNIC|20100101|Org B|CN|APNIC|20200115|RESOURCE_TRANSFER
ipv6|2001:db8::|Org C|US|ARIN|20100202|Org D|JP|APNIC|20210320|INTER_RIR_TRANSFER
`

const sampleTransfersAllMD5 = `MD5 (file) = 0123456789abcdef0123456789abcdef`

const sampleTelemetryJSON = `{
  "RDAP": {
    "date_range": {"start": "2026-07-01T06:00:00Z", "end": "2026-07-01T07:00:00Z"},
    "total_queries": 3070925,
    "total_asns": 1737,
    "query_type_distribution": {"ip": 3030224, "autnum": 28141, "entity": 10441, "domain": 2044},
    "asns": [
      {"asn": "45102", "query_count": 2274463, "query_count_by_type": {"ip": 2274457, "entity": 6}}
    ]
  }
}`

const sampleTelemetryMD5 = `0123456789abcdef0123456789abcdef  file`

const sampleChangesData = `{"count":3,"stats-begin":"https://ftp.apnic.net/stats/apnic/2026/delegated-apnic-extended-20260626.gz","stats-end":"https://ftp.apnic.net/stats/apnic/2026/delegated-apnic-extended-20260627.gz","timestamp":"2026-06-26 15:23:38","version":"0.1"}
{"cc":"IN","custodian":"A91ED89F","resources":["160.236.32.0/23"],"status":"allocated","timestamp":"2026-06-25T22:16:15","type":"delegated"}
{"cc":"BD","resources":["202.136.88.0/22"],"timestamp":"2026-06-25T22:27:30","type":"cc-changed"}
{"cc":"IN","custodian":"A9139ECA","resources":["152478"],"status":"allocated","timestamp":"2026-06-25T23:36:41","type":"delegated"}
`

const sampleRDAPNetworkJSON = `{
  "rdapConformance": ["rdap_level_0"],
  "objectClassName": "ip network",
  "handle": "1.1.1.0 - 1.1.1.255",
  "startAddress": "1.1.1.0",
  "endAddress": "1.1.1.255",
  "ipVersion": "v4",
  "name": "APNIC-LABS",
  "country": "AU",
  "type": "ASSIGNED PORTABLE",
  "status": ["active"],
  "cidr0_cidrs": [{"v4prefix": "1.1.1.0", "length": 24}],
  "entities": [
    {
      "objectClassName": "entity",
      "handle": "AIC3-AP",
      "roles": ["administrative", "technical"],
      "events": [{"eventAction": "registration", "eventDate": "2023-04-26T00:42:16Z"}]
    }
  ],
  "events": [
    {"eventAction": "registration", "eventDate": "2011-08-10T23:12:35Z"},
    {"eventAction": "last changed", "eventDate": "2023-04-26T22:57:58Z"}
  ],
  "remarks": [{"title": "description", "description": ["APNIC and Cloudflare DNS Resolver project"]}],
  "port43": "whois.apnic.net"
}`

const sampleRDAPAutnumJSON = `{
  "rdapConformance": ["rdap_level_0"],
  "objectClassName": "autnum",
  "handle": "AS13335",
  "startAutnum": 13335,
  "endAutnum": 13335,
  "name": "CLOUDFLARE",
  "type": "ASSIGNED PORTABLE",
  "status": ["active"],
  "country": "AU",
  "entities": [],
  "events": [{"eventAction": "registration", "eventDate": "2010-07-14T00:00:00Z"}],
  "remarks": [],
  "port43": "whois.apnic.net"
}`

const sampleRDAPDomainJSON = `{
  "rdapConformance": ["rdap_level_0"],
  "objectClassName": "domain",
  "handle": "1.0.0.1.in-addr.arpa",
  "ldhName": "1.0.0.1.in-addr.arpa",
  "nameservers": [{"ldhName": "ns1.example.com"}],
  "entities": [],
  "events": [{"eventAction": "registration", "eventDate": "2018-03-27T00:30:48Z"}],
  "port43": "whois.apnic.net"
}`

const sampleRDAPEntityJSON = `{
  "rdapConformance": ["rdap_level_0"],
  "objectClassName": "entity",
  "handle": "AIC3-AP",
  "roles": ["administrative", "technical"],
  "events": [{"eventAction": "registration", "eventDate": "2023-04-26T00:42:16Z"}],
  "links": [{"rel": "self", "href": "https://rdap.apnic.net/entity/AIC3-AP", "type": "application/rdap+json"}],
  "vcardArray": ["vcard", [["fn", {}, "text", "APNIC Contact"]]],
  "port43": "whois.apnic.net"
}`

const sampleRDAPSearchJSON = `{
  "rdapConformance": ["rdap_level_0"],
  "entitySearchResults": [
    {"objectClassName": "entity", "handle": "AIC3-AP", "roles": ["administrative"]},
    {"objectClassName": "entity", "handle": "IRA1-AP", "roles": ["technical"]}
  ],
  "port43": "whois.apnic.net"
}`

const sampleRDAPDomainsSearchJSON = `{
  "rdapConformance": ["rdap_level_0", "nro_rdap_profile_0"],
  "domainSearchResults": [
    {"objectClassName": "domain", "handle": "1.in-addr.arpa", "ldhName": "1.in-addr.arpa"},
    {"objectClassName": "domain", "handle": "2.in-addr.arpa", "ldhName": "2.in-addr.arpa"}
  ],
  "port43": "whois.apnic.net"
}`

const sampleRDAPHelpJSON = `{
  "rdapConformance": ["rdap_level_0", "history_version_0", "cidr0", "nro_rdap_profile_0", "redirect_with_content"],
  "notices": [
    {"title": "Terms of Service", "description": ["By using the APNIC RDAP service you agree to the APNIC terms of service."]},
    {"title": "Inaccuracy Reports", "description": ["Use the APNIC inaccuracy report form."]}
  ],
  "port43": "whois.apnic.net"
}`

const sampleRDAPNotFoundJSON = `{
  "errorCode": 404,
  "title": "Not Found",
  "description": ["The server has not found anything matching the Request-URI."]
}`

const sampleWhoisResponse = `% Whois information

inetnum:        1.1.1.0 - 1.1.1.255
CIDR:           1.1.1.0/24
country:        AU
descr:          APNIC and Cloudflare DNS Resolver project
org:            APNIC Research and Development
parent:         1.0.0.0 - 1.255.255.255
created:        2011-08-10T23:12:35Z
last-modified:  2023-04-26T22:57:58Z
`
