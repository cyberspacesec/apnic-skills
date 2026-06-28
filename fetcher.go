package apnic

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// FetchDelegatedEntries fetches the latest standard delegated stats from APNIC.
func (c *Client) FetchDelegatedEntries(ctx context.Context) ([]DelegatedEntry, error) {
	result, err := c.FetchDelegatedResult(ctx, "")
	if err != nil {
		return nil, err
	}
	return result.Entries, nil
}

// FetchDelegatedEntriesByDate fetches delegated stats for a specific date.
// date must be in YYYYMMDD format.
func (c *Client) FetchDelegatedEntriesByDate(ctx context.Context, date string) ([]DelegatedEntry, error) {
	result, err := c.FetchDelegatedResult(ctx, date)
	if err != nil {
		return nil, err
	}
	return result.Entries, nil
}

// FetchDelegatedResult fetches and parses the full delegated stats result including header and summaries.
// If date is empty, fetches the latest; otherwise fetches the specified date (YYYYMMDD).
func (c *Client) FetchDelegatedResult(ctx context.Context, date string) (*DelegatedResult, error) {
	url := buildStatsURL(c.statsBaseURL, "delegated", date)
	body, err := c.fetchText(ctx, url)
	if err != nil {
		return nil, err
	}
	return parseDelegatedFull(strings.NewReader(body))
}

// FetchDelegatedResultByYear fetches delegated stats for a specific year.
// Returns the result from the latest available file in that year.
func (c *Client) FetchDelegatedResultByYear(ctx context.Context, year int) (*DelegatedResult, error) {
	url := fmt.Sprintf("%s%d/delegated-apnic-extended-%d1231", c.statsBaseURL, year, year)
	body, err := c.fetchText(ctx, url)
	if err != nil {
		return nil, err
	}
	return parseDelegatedFull(strings.NewReader(body))
}

// fetchText performs an HTTP GET request and returns the response body as a string.
func (c *Client) fetchText(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("request creation failed: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "text/plain")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d for URL: %s", resp.StatusCode, url)
	}

	var buf strings.Builder
	if _, err := io.Copy(&buf, resp.Body); err != nil {
		return "", fmt.Errorf("read response failed: %w", err)
	}
	return buf.String(), nil
}

// parseDelegatedFull parses the complete delegated stats file including header, summaries, and entries.
func parseDelegatedFull(r io.Reader) (*DelegatedResult, error) {
	scanner := bufio.NewScanner(r)
	result := &DelegatedResult{
		Summaries: make([]StatsSummary, 0),
		Entries:   make([]DelegatedEntry, 0, 5000),
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse header line
		if isHeaderLine(line) {
			header, err := parseStatsHeader(line)
			if err == nil {
				result.Header = *header
			}
			continue
		}

		// Parse summary line
		if isSummaryLine(line) {
			summary, err := parseSummaryLine(line)
			if err == nil {
				result.Summaries = append(result.Summaries, *summary)
			}
			continue
		}

		// Parse data line
		parts := strings.Split(line, "|")
		if len(parts) < 7 {
			continue
		}

		entry := DelegatedEntry{
			Registry:   parts[0],
			Country:    parts[1],
			Type:       parts[2],
			Start:      parts[3],
			Status:     parts[6],
			Extensions: parts[7:],
		}

		var parseErr error
		switch entry.Type {
		case "ipv4":
			entry.Value, parseErr = parseIPv4Count(parts[4])
		case "ipv6":
			entry.Value, parseErr = parseIPv6Prefix(parts[4])
		case "asn":
			entry.Value, parseErr = parseASNCount(parts[4])
		default:
			continue
		}

		if parseErr != nil {
			continue
		}

		if date, err := parseStatsDate(parts[5]); err == nil {
			entry.Date = date
		}

		result.Entries = append(result.Entries, entry)
	}

	return result, scanner.Err()
}

// parseDelegatedFullFromString parses the complete delegated stats from a string.
func parseDelegatedFullFromString(data string) (*DelegatedResult, error) {
	return parseDelegatedFull(strings.NewReader(data))
}

// parseDelegatedData parses only the data entries from a delegated stats file (legacy compatibility).
func parseDelegatedData(r io.Reader) ([]DelegatedEntry, error) {
	result, err := parseDelegatedFull(r)
	if err != nil {
		return nil, err
	}
	return result.Entries, nil
}
