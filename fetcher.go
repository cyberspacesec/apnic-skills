package apnic

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func (c *Client) FetchDelegatedEntries(ctx context.Context) ([]DelegatedEntry, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest", nil)
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "text/plain")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return parseDelegatedData(resp.Body)
}

func parseDelegatedData(r io.Reader) ([]DelegatedEntry, error) {
	scanner := bufio.NewScanner(r)
	entries := make([]DelegatedEntry, 0, 5000)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) < 7 {
			continue
		}

		entry := DelegatedEntry{
			Registry:   parts[0],
			Country:    parts[1],
			Type:       parts[2],
			Start:      parts[3],
			Status:     parts[5],
			Extensions: parts[6:],
		}

		var parseErr error
		switch entry.Type {
		case "ipv4":
			entry.Value, parseErr = parseIPv4Count(parts[4])
		case "ipv6":
			entry.Value, parseErr = parseIPv6Prefix(parts[4])
		case "asn":
			entry.Value, parseErr = parseASNValue(parts[4])
		default:
			continue
		}

		if parseErr != nil {
			continue
		}

		if date, err := time.Parse("20060102", parts[4]); err == nil {
			entry.Date = date
		}

		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}
