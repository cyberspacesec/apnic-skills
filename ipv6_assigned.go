package apnic

import (
	"bufio"
	"context"
	"io"
	"strings"
)

// FetchIPv6AssignedEntries fetches the latest delegated-apnic-ipv6-assigned stats from APNIC.
// This file lists individual IPv6 assignments (a per-prefix view, distinct from the
// aggregated "assigned" stats which count assignments by prefix size).
func (c *Client) FetchIPv6AssignedEntries(ctx context.Context) ([]IPv6AssignedEntry, error) {
	result, err := c.FetchIPv6AssignedResult(ctx, "")
	if err != nil {
		return nil, err
	}
	return result.Entries, nil
}

// FetchIPv6AssignedEntriesByDate fetches delegated-apnic-ipv6-assigned stats for a specific date.
// date must be in YYYYMMDD format.
func (c *Client) FetchIPv6AssignedEntriesByDate(ctx context.Context, date string) ([]IPv6AssignedEntry, error) {
	result, err := c.FetchIPv6AssignedResult(ctx, date)
	if err != nil {
		return nil, err
	}
	return result.Entries, nil
}

// FetchIPv6AssignedResult fetches and parses the full delegated-apnic-ipv6-assigned stats
// result including header and summaries.
// If date is empty, fetches the latest; otherwise fetches the specified date (YYYYMMDD).
func (c *Client) FetchIPv6AssignedResult(ctx context.Context, date string) (*IPv6AssignedResult, error) {
	url := buildStatsURL(c.statsBaseURL, "delegated-ipv6-assigned", date)
	r, err := c.fetchReader(ctx, url)
	if err != nil {
		return nil, err
	}
	return parseIPv6AssignedFull(r)
}

// parseIPv6AssignedFull parses the complete delegated-apnic-ipv6-assigned stats file.
// Row format: registry|cc|ipv6|start|prefix|date  (6 fields, no status/extensions)
func parseIPv6AssignedFull(r io.Reader) (*IPv6AssignedResult, error) {
	scanner := bufio.NewScanner(r)
	result := &IPv6AssignedResult{
		Summaries: make([]StatsSummary, 0),
		Entries:   make([]IPv6AssignedEntry, 0, 1000),
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

		// Parse data line: registry|cc|ipv6|start|prefix|date
		parts := strings.Split(line, "|")
		if len(parts) < 6 {
			continue
		}

		// Only ipv6 rows are present in this file.
		if parts[2] != "ipv6" {
			continue
		}

		prefix, err := parseIPv6Prefix(parts[4])
		if err != nil {
			continue
		}

		entry := IPv6AssignedEntry{
			Registry: parts[0],
			Country:  parts[1],
			Start:    parts[3],
			Value:    prefix,
		}

		if date, err := parseStatsDate(parts[5]); err == nil {
			entry.Date = date
		}

		result.Entries = append(result.Entries, entry)
	}

	return result, scanner.Err()
}
