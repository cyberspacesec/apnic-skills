package apnic

import (
	"context"
	"net"
	"net/http"
	"time"
)

// dialFunc is the signature for dialing a network connection.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Client is the APNIC SDK client that provides access to all APNIC services.
type Client struct {
	httpClient   *http.Client
	whoisServer  string
	whoisTimeout time.Duration
	rdapBaseURL  string
	statsBaseURL string // base URL for stats/FTP data, defaults to "https://ftp.apnic.net/apnic/stats/apnic/"
	cache        *cache
	userAgent    string
	dialWhois    dialFunc // optional override for whois dial, used in testing
}

// Option is a functional option for configuring the Client.
type Option func(*Client)

// NewClient creates a new APNIC client with the given options.
func NewClient(opts ...Option) *Client {
	c := &Client{
		httpClient:   &http.Client{Timeout: 15 * time.Second},
		whoisServer:  "whois.apnic.net:43",
		whoisTimeout: 10 * time.Second,
		rdapBaseURL:  "https://rdap.apnic.net",
		statsBaseURL: "https://ftp.apnic.net/apnic/stats/apnic/",
		cache:        newCache(30 * time.Minute),
		userAgent:    "APNIC-Go-SDK/1.0 (security)",
	}

	for _, opt := range opts {
		opt(c)
	}
	return c
}

// WithHTTPClient sets a custom HTTP client for API requests.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		c.httpClient = hc
	}
}

// WithCacheTTL sets the cache time-to-live duration.
func WithCacheTTL(ttl time.Duration) Option {
	return func(c *Client) {
		c.cache.ttl = ttl
	}
}

// WithUserAgent sets a custom User-Agent header for requests.
func WithUserAgent(ua string) Option {
	return func(c *Client) {
		c.userAgent = ua
	}
}

// WithRDAPBaseURL sets a custom base URL for RDAP queries.
func WithRDAPBaseURL(url string) Option {
	return func(c *Client) {
		c.rdapBaseURL = url
	}
}

// WithWhoisServer sets a custom Whois server address.
func WithWhoisServer(server string) Option {
	return func(c *Client) {
		c.whoisServer = server
	}
}

// WithWhoisTimeout sets the Whois connection timeout.
func WithWhoisTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		c.whoisTimeout = timeout
	}
}

// WithStatsBaseURL sets a custom base URL for stats/FTP data requests.
func WithStatsBaseURL(url string) Option {
	return func(c *Client) {
		c.statsBaseURL = url
	}
}
