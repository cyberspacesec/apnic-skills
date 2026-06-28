package apnic

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseIPv4Count parses an IPv4 host count value.
func parseIPv4Count(s string) (int64, error) {
	count, err := strconv.ParseInt(s, 10, 64)
	if err != nil || count <= 0 {
		return 0, fmt.Errorf("%w: %s", ErrInvalidIP, s)
	}
	return count, nil
}

// parseIPv6Prefix parses an IPv6 prefix length value.
func parseIPv6Prefix(s string) (int64, error) {
	prefix, err := strconv.ParseInt(s, 10, 64)
	if err != nil || prefix < 0 || prefix > 128 {
		return 0, fmt.Errorf("%w: %s", ErrInvalidIP, s)
	}
	return prefix, nil
}

// parseASNValue parses an ASN value from delegated stats.
// In delegated stats files, ASN values are plain integers (not "AS" prefixed).
func parseASNValue(s string) (int64, error) {
	asn, err := strconv.ParseInt(s, 10, 64)
	if err != nil || asn < 0 {
		return 0, fmt.Errorf("%w: %s", ErrInvalidASN, s)
	}
	return asn, nil
}

// parseASNCount parses an ASN count value from delegated stats.
func parseASNCount(s string) (int64, error) {
	count, err := strconv.ParseInt(s, 10, 64)
	if err != nil || count <= 0 {
		return 0, fmt.Errorf("%w: %s", ErrInvalidASN, s)
	}
	return count, nil
}

// parseStatsHeader parses the version/header line of a stats file.
// Format: version|registry|serial|records|startdate|enddate|UTCoffset
func parseStatsHeader(line string) (*StatsFileHeader, error) {
	parts := strings.Split(line, "|")
	if len(parts) < 7 {
		return nil, fmt.Errorf("%w: invalid header line", ErrInvalidStatsType)
	}

	serial, _ := strconv.ParseInt(parts[2], 10, 64)
	records, _ := strconv.ParseInt(parts[3], 10, 64)
	utcOffset, _ := strconv.Atoi(parts[6])

	var startDate, endDate time.Time
	if d, err := time.Parse("20060102", parts[4]); err == nil {
		startDate = d
	}
	if d, err := time.Parse("20060102", parts[5]); err == nil {
		endDate = d
	}

	return &StatsFileHeader{
		Version:   parts[0],
		Registry:  parts[1],
		Serial:    serial,
		Records:   records,
		StartDate: startDate,
		EndDate:   endDate,
		UTCOffset: utcOffset,
	}, nil
}

// parseSummaryLine parses a summary line from a stats file.
// Format: registry|*|type|*|count|summary
func parseSummaryLine(line string) (*StatsSummary, error) {
	parts := strings.Split(line, "|")
	if len(parts) < 6 || parts[5] != "summary" {
		return nil, fmt.Errorf("%w: invalid summary line", ErrInvalidStatsType)
	}

	count, _ := strconv.ParseInt(parts[4], 10, 64)

	return &StatsSummary{
		Registry: parts[0],
		Type:     parts[2],
		Count:    count,
	}, nil
}

// isSummaryLine checks if a line is a summary line.
func isSummaryLine(line string) bool {
	parts := strings.Split(line, "|")
	return len(parts) >= 6 && parts[5] == "summary"
}

// isHeaderLine checks if a line is a header (version) line.
func isHeaderLine(line string) bool {
	parts := strings.Split(line, "|")
	if len(parts) < 7 {
		return false
	}
	// Version lines start with a version number like "2" or "2.3"
	v := parts[0]
	if _, err := strconv.ParseFloat(v, 64); err == nil {
		return true
	}
	return false
}

// buildStatsURL constructs the URL for a stats data file.
// dataType: "delegated", "delegated-extended", "assigned", "legacy", "delegated-ipv6-assigned"
// date: optional date in "YYYYMMDD" format; if empty, uses "latest"
func buildStatsURL(baseURL, dataType, date string) string {
	if date == "" {
		return baseURL + dataType + "-apnic-latest"
	}
	return baseURL + dataType + "-apnic-" + date
}

// buildStatsMD5URL constructs the URL for a stats file MD5 checksum.
func buildStatsMD5URL(baseURL, dataType, date string) string {
	return buildStatsURL(baseURL, dataType, date) + ".md5"
}

// buildStatsASCURL constructs the URL for a stats file ASC signature.
func buildStatsASCURL(baseURL, dataType, date string) string {
	return buildStatsURL(baseURL, dataType, date) + ".asc"
}

// parseOpaqueID extracts the opaque-id from a stats record.
func parseOpaqueID(s string) string {
	return strings.TrimSpace(s)
}

// parseStatsDate parses a date string in YYYYMMDD format.
func parseStatsDate(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "00000000" {
		return time.Time{}, nil
	}
	t, err := time.Parse("20060102", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %s", ErrInvalidDate, s)
	}
	return t, nil
}

// FormatDate formats a time.Time to YYYYMMDD string for use in stats file URLs.
func FormatDate(t time.Time) string {
	return t.Format("20060102")
}

// ParseDate parses a YYYYMMDD date string.
func ParseDate(s string) (time.Time, error) {
	return parseStatsDate(s)
}
