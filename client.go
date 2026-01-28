package apnic

import (
	"net/http"
	"time"
)

type Client struct {
	httpClient   *http.Client
	whoisServer  string
	whoisTimeout time.Duration
	cache        *cache
	userAgent    string
}

type Option func(*Client)

func NewClient(opts ...Option) *Client {
	c := &Client{
		httpClient:   &http.Client{Timeout: 15 * time.Second},
		whoisServer:  "whois.apnic.net:43",
		whoisTimeout: 10 * time.Second,
		cache: &cache{
			ttl: 30 * time.Minute,
		},
		userAgent: "APNIC-Go-SDK/1.0 (security)",
	}

	for _, opt := range opts {
		opt(c)
	}
	return c
}

func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		c.httpClient = hc
	}
}

func WithCacheTTL(ttl time.Duration) Option {
	return func(c *Client) {
		c.cache.ttl = ttl
	}
}

func WithUserAgent(ua string) Option {
	return func(c *Client) {
		c.userAgent = ua
	}
}
