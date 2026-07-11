package stats

import (
	"bufio"
	"context"
	"io"
	"strings"
)

// FetchLegacyEntries fetches the latest legacy stats from APNIC.
// Legacy stats contain historical resource records that were registered before APNIC's establishment.
func (c *Client) FetchLegacyEntries(ctx context.Context) (*LegacyResult, error) {
	return c.FetchLegacyResult(ctx, "")
}

// FetchLegacyEntriesByDate fetches legacy stats for a specific date.
// date must be in YYYYMMDD format.
func (c *Client) FetchLegacyEntriesByDate(ctx context.Context, date string) (*LegacyResult, error) {
	return c.FetchLegacyResult(ctx, date)
}

// FetchLegacyResult fetches and parses the full legacy stats result.
// If date is empty, fetches the latest; otherwise fetches the specified date (YYYYMMDD).
func (c *Client) FetchLegacyResult(ctx context.Context, date string) (*LegacyResult, error) {
	url := buildStatsURL(c.statsBaseURL, "legacy", date)
	r, err := c.fetchReader(ctx, url)
	if err != nil {
		return nil, err
	}
	return parseLegacyFull(r)
}

// parseLegacyFull parses the complete legacy stats file.
// Legacy format: version|registry|serial|records|startdate|enddate|UTCoffset
// followed by: registry|cc|type|start|value|date|status
// Note: Legacy entries may have empty country codes.
func parseLegacyFull(r io.Reader) (*LegacyResult, error) {
	scanner := bufio.NewScanner(r)
	result := &LegacyResult{
		Summaries: make([]StatsSummary, 0),
		Entries:   make([]LegacyEntry, 0, 2000),
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
		if len(parts) < 7 {
			continue
		}

		entry := LegacyEntry{
			Registry: parts[0],
			Country:  parts[1], // may be empty for legacy entries
			Type:     parts[2],
			Start:    parts[3],
			Status:   parts[6],
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
