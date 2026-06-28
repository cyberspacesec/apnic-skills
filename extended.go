package apnic

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
)

// FetchExtendedEntries fetches the latest extended delegated stats from APNIC.
// Extended stats include the OpaqueID field that uniquely identifies the resource holder.
func (c *Client) FetchExtendedEntries(ctx context.Context) (*ExtendedResult, error) {
	return c.FetchExtendedResult(ctx, "")
}

// FetchExtendedEntriesByDate fetches extended delegated stats for a specific date.
// date must be in YYYYMMDD format.
func (c *Client) FetchExtendedEntriesByDate(ctx context.Context, date string) (*ExtendedResult, error) {
	return c.FetchExtendedResult(ctx, date)
}

// FetchExtendedResult fetches and parses the full extended delegated stats result.
// If date is empty, fetches the latest; otherwise fetches the specified date (YYYYMMDD).
func (c *Client) FetchExtendedResult(ctx context.Context, date string) (*ExtendedResult, error) {
	url := buildStatsURL(c.statsBaseURL, "delegated-extended", date)
	body, err := c.fetchText(ctx, url)
	if err != nil {
		return nil, err
	}
	return parseExtendedFull(strings.NewReader(body))
}

// FetchExtendedResultByYear fetches extended delegated stats for a specific year.
func (c *Client) FetchExtendedResultByYear(ctx context.Context, year int) (*ExtendedResult, error) {
	url := fmt.Sprintf("%s%d/delegated-apnic-extended-%d1231.gz", c.statsBaseURL, year, year)
	body, err := c.fetchText(ctx, url)
	if err != nil {
		return nil, err
	}
	return parseExtendedFull(strings.NewReader(body))
}

// parseExtendedFull parses the complete extended delegated stats file.
// Extended format: registry|cc|type|start|value|date|status|opaque-id[|extensions...]
func parseExtendedFull(r io.Reader) (*ExtendedResult, error) {
	scanner := bufio.NewScanner(r)
	result := &ExtendedResult{
		Summaries: make([]StatsSummary, 0),
		Entries:   make([]DelegatedExtendedEntry, 0, 10000),
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

		// Parse data line — extended format has at least 8 fields
		parts := strings.Split(line, "|")
		if len(parts) < 8 {
			continue
		}

		entry := DelegatedExtendedEntry{
			Registry:   parts[0],
			Country:    parts[1],
			Type:       parts[2],
			Start:      parts[3],
			Status:     parts[6],
			OpaqueID:   parseOpaqueID(parts[7]),
			Extensions: parts[8:],
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

// parseExtendedFullFromString parses the complete extended delegated stats from a string.
func parseExtendedFullFromString(data string) (*ExtendedResult, error) {
	return parseExtendedFull(strings.NewReader(data))
}
