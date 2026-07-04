package apnic

import (
	"bufio"
	"context"
	"io"
	"strings"
)

// FetchAssignedEntries fetches the latest assigned stats from APNIC.
// Assigned stats show aggregated assignment counts by prefix size per country.
func (c *Client) FetchAssignedEntries(ctx context.Context) (*AssignedResult, error) {
	return c.FetchAssignedResult(ctx, "")
}

// FetchAssignedEntriesByDate fetches assigned stats for a specific date.
// date must be in YYYYMMDD format.
func (c *Client) FetchAssignedEntriesByDate(ctx context.Context, date string) (*AssignedResult, error) {
	return c.FetchAssignedResult(ctx, date)
}

// FetchAssignedResult fetches and parses the full assigned stats result.
// If date is empty, fetches the latest; otherwise fetches the specified date (YYYYMMDD).
func (c *Client) FetchAssignedResult(ctx context.Context, date string) (*AssignedResult, error) {
	url := buildStatsURL(c.statsBaseURL, "assigned", date)
	r, err := c.fetchReader(ctx, url)
	if err != nil {
		return nil, err
	}
	return parseAssignedFull(r)
}

// parseAssignedFull parses the complete assigned stats file.
// Assigned format: registry|cc|type||prefix_size||status|||count
// Example: apnic|ae|ipv4||4||assigned|||1
func parseAssignedFull(r io.Reader) (*AssignedResult, error) {
	scanner := bufio.NewScanner(r)
	result := &AssignedResult{
		Summaries: make([]StatsSummary, 0),
		Entries:   make([]AssignedEntry, 0, 1000),
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

		parts := strings.Split(line, "|")
		if len(parts) < 9 {
			continue
		}

		// Skip non-ipv4/ipv6 entries (assigned stats only have ipv4/ipv6)
		entryType := parts[2]
		if entryType != "ipv4" && entryType != "ipv6" {
			continue
		}

		var count int64
		if parsed, err := parseIPv4Count(parts[8]); err == nil {
			count = parsed
		}

		entry := AssignedEntry{
			Registry: parts[0],
			Country:  parts[1],
			Type:     entryType,
			Prefix:   parts[4], // prefix size (e.g. "4", "256")
			Count:    count,
			Status:   parts[6],
		}

		result.Entries = append(result.Entries, entry)
	}

	return result, scanner.Err()
}
