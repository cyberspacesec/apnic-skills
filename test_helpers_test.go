package apnic

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// md5Hash computes the MD5 hash of a string.
func md5Hash(data string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(data)))
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
// both stats (FTP) and RDAP requests.
func newTestClient(handler http.HandlerFunc) (*Client, *httptest.Server) {
	server := httptest.NewServer(handler)
	client := NewClient(
		WithHTTPClient(server.Client()),
		WithRDAPBaseURL(server.URL),
		WithCacheTTL(1*time.Hour),
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
// hitting real servers.
func allStatsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		w.Header().Set("Content-Type", "text/plain")

		switch {
		case strings.Contains(path, "delegated-extended"):
			w.Write([]byte(sampleExtendedData))
		case strings.Contains(path, "assigned"):
			w.Write([]byte(sampleAssignedData))
		case strings.Contains(path, "legacy"):
			w.Write([]byte(sampleLegacyData))
		case strings.Contains(path, "delegated"):
			w.Write([]byte(sampleDelegatedData))
		case strings.Contains(path, "transfers"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(sampleTransfersJSON))
		case strings.Contains(path, "changes"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(sampleChangesData))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(sampleRDAPNotFoundJSON))
		}
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
		case strings.Contains(path, "/search"):
			w.Write([]byte(sampleRDAPSearchJSON))
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
			strings.HasPrefix(path, "/entity/") ||
			strings.HasPrefix(path, "/search") {
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
  "results": [
    {"objectClassName": "ip network", "handle": "1.1.1.0 - 1.1.1.255", "name": "APNIC-LABS"}
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
