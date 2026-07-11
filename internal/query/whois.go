package query

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/cyberspacesec/apnic-skills/internal/models"
	"github.com/cyberspacesec/apnic-skills/internal/transport"
)

// QueryWhois performs a raw Whois query against the APNIC Whois server.
// Returns the raw Whois response text.
func QueryWhois(ctx context.Context, c *transport.Client, query string) (string, error) {
	return queryWhois(ctx, c, query)
}

// QueryWhoisIP performs a Whois query for an IP address.
// This is a convenience method that queries and parses the result.
func QueryWhoisIP(ctx context.Context, c *transport.Client, ip string) (*models.WhoisInfo, error) {
	raw, err := queryWhois(ctx, c, ip)
	if err != nil {
		return nil, err
	}
	info := ParseWhoisResponse(raw)
	return &info, nil
}

// QueryWhoisASN performs a Whois query for an Autonomous System Number.
// asn should be a plain number (e.g. 13335), not "AS13335".
func QueryWhoisASN(ctx context.Context, c *transport.Client, asn int64) (*models.WhoisInfo, error) {
	query := fmt.Sprintf("AS%d", asn)
	raw, err := queryWhois(ctx, c, query)
	if err != nil {
		return nil, err
	}
	info := ParseWhoisResponse(raw)
	return &info, nil
}

// QueryWhoisWithFlags performs a Whois query with additional flags.
// Common flags: "B" (brief), "r" (no recursion), "l" (one level less specific).
func QueryWhoisWithFlags(ctx context.Context, c *transport.Client, query string, flags string) (string, error) {
	if flags != "" {
		query = flags + " " + query
	}
	return queryWhois(ctx, c, query)
}

// queryWhois performs the actual TCP Whois query.
func queryWhois(ctx context.Context, c *transport.Client, query string) (string, error) {
	// Apply the same anti-scraping pacing to whois as to HTTP so high-frequency
	// whois queries don't trip rate limits. Whois has no browser headers (it is
	// a plain TCP protocol), but jitter + rate limiting still apply.
	if err := c.WaitRateLimit(ctx); err != nil {
		return "", err
	}
	c.Jitter(ctx)

	var conn net.Conn
	var err error

	if d := c.DialWhois(); d != nil {
		conn, err = d(ctx, "tcp", c.WhoisServer())
	} else {
		dialer := net.Dialer{Timeout: c.WhoisTimeout()}
		conn, err = dialer.DialContext(ctx, "tcp", c.WhoisServer())
	}
	if err != nil {
		return "", fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	query = strings.TrimSpace(query) + "\r\n"
	if _, err := conn.Write([]byte(query)); err != nil {
		return "", fmt.Errorf("write failed: %w", err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, conn); err != nil {
		return "", fmt.Errorf("read failed: %w", err)
	}

	return buf.String(), nil
}

// ParseWhoisResponse parses a raw Whois response into a structured WhoisInfo.
// It extracts network, CIDR, country, organization, parent, and date information.
func ParseWhoisResponse(response string) models.WhoisInfo {
	info := models.WhoisInfo{}
	scanner := bufio.NewScanner(strings.NewReader(response))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "inetnum", "inet6num":
			info.Network = value
		case "CIDR":
			info.CIDR = strings.Split(value, ",")
		case "country":
			info.Country = value
		case "descr", "org-name", "org":
			if info.OrgName == "" {
				info.OrgName = value
			}
		case "parent":
			info.Parent = value
		case "created":
			if t, err := parseWhoisDate(value); err == nil {
				info.Created = t
			}
		case "last-modified":
			if t, err := parseWhoisDate(value); err == nil {
				info.LastUpdated = t
			}
		}
	}

	return info
}

// parseWhoisDate attempts to parse a date string from Whois responses.
func parseWhoisDate(s string) (time.Time, error) {
	formats := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
		"20060102",
		"2006-01-02",
	}
	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized date format: %s", s)
}
