package query

import (
	"context"
	"encoding/json"
	"fmt"
)

// FetchTelemetry fetches the APNIC whois/RDAP service query telemetry
// (whois-rdap-stats.json), published hourly with per-query-type distribution
// and top-queried ASNs. date == "" fetches the latest; a YYYYMMDD date fetches
// the archived snapshot for that day.
func (c *Client) FetchTelemetry(ctx context.Context, date string) (*WhoisRDAPTelemetry, error) {
	url := buildTelemetryURL(c.ftpBaseURL, date)
	body, err := c.fetchText(ctx, url)
	if err != nil {
		return nil, err
	}
	var t WhoisRDAPTelemetry
	if err := json.Unmarshal([]byte(body), &t); err != nil {
		return nil, fmt.Errorf("telemetry JSON decode failed: %w", err)
	}
	return &t, nil
}

// FetchTelemetryMD5 fetches the MD5 checksum for the telemetry JSON.
func (c *Client) FetchTelemetryMD5(ctx context.Context, date string) (string, error) {
	url := buildTelemetrySidecarURL(c.ftpBaseURL, date)
	content, err := c.fetchText(ctx, url)
	if err != nil {
		return "", err
	}
	return parseMD5Checksum(content)
}
