package transport

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

// statsFileName returns the base file name for a stats data file of the given
// type and date, using APNIC's naming convention:
//   - latest:  {type}-apnic-latest   (e.g. delegated-apnic-latest)
//   - dated:   delegated-apnic-{date}, delegated-apnic-extended-{date},
//              delegated-apnic-ipv6-assigned-{date}, assigned-apnic-{date},
//              legacy-apnic-{date}
func statsFileName(dataType, date string) string {
	if date == "" {
		if dataType == "delegated" || strings.HasPrefix(dataType, "delegated-") {
			variant := strings.TrimPrefix(dataType, "delegated-")
			if variant == "delegated" {
				return "delegated-apnic-latest"
			}
			return "delegated-apnic-" + variant + "-latest"
		}
		return dataType + "-apnic-latest"
	}
	if dataType == "delegated" || strings.HasPrefix(dataType, "delegated-") {
		variant := strings.TrimPrefix(dataType, "delegated-")
		if variant == "delegated" {
			return "delegated-apnic-" + date
		}
		return "delegated-apnic-" + variant + "-" + date
	}
	return dataType + "-apnic-" + date
}

// buildStatsURL constructs the URL for a stats data file.
// For the latest file (date == "") the file lives at the stats root.
// For a specific date (YYYYMMDD) the file lives under a {year}/ subdirectory and
// is gzip-compressed with a ".gz" suffix.
// dataType: "delegated", "delegated-extended", "delegated-ipv6-assigned",
// "assigned", "legacy".
func buildStatsURL(baseURL, dataType, date string) string {
	name := statsFileName(dataType, date)
	if date == "" {
		return baseURL + name
	}
	return fmt.Sprintf("%s%s/%s.gz", baseURL, date[:4], name)
}

// buildStatsMD5URL constructs the URL for a stats file MD5 checksum.
// Latest checksums are plain text; dated checksums are gzip-compressed (.md5.gz).
func buildStatsMD5URL(baseURL, dataType, date string) string {
	name := statsFileName(dataType, date)
	if date == "" {
		return baseURL + name + ".md5"
	}
	return fmt.Sprintf("%s%s/%s.md5.gz", baseURL, date[:4], name)
}

// buildStatsASCURL constructs the URL for a stats file ASC (PGP) signature.
// Latest signatures are plain text; dated signatures are gzip-compressed (.asc.gz).
func buildStatsASCURL(baseURL, dataType, date string) string {
	name := statsFileName(dataType, date)
	if date == "" {
		return baseURL + name + ".asc"
	}
	return fmt.Sprintf("%s%s/%s.asc.gz", baseURL, date[:4], name)
}

// parseOpaqueID extracts the opaque-id from a stats record.
func parseOpaqueID(s string) string {
	return strings.TrimSpace(s)
}

// buildTransfersAllURL constructs the URL for the cumulative transfers-all log.
// date == "" fetches the latest (transfer-all-apnic-latest); a YYYYMMDD date
// fetches the archived daily snapshot under transfers-all/apnic/{YYYY}/. The
// data lives under the FTP root (not the stats subdirectory), so it uses
// ftpBaseURL.
func buildTransfersAllURL(ftpBaseURL, date string) string {
	if date == "" {
		return ftpBaseURL + "transfers-all/apnic/transfer-all-apnic-latest"
	}
	// date is YYYYMMDD; the year prefix is the first 4 chars.
	return fmt.Sprintf("%stransfers-all/apnic/%s/transfer-all-apnic-%s", ftpBaseURL, date[:4], date)
}

// buildTransfersAllSidecarURL constructs the URL for the .md5 or .asc sidecar of
// the cumulative transfers-all log. suffix is ".md5" or ".asc".
func buildTransfersAllSidecarURL(ftpBaseURL, date, suffix string) string {
	return buildTransfersAllURL(ftpBaseURL, date) + suffix
}

// buildTelemetryURL constructs the URL for the whois-rdap-stats telemetry JSON.
// date == "" fetches the latest; a YYYYMMDD date fetches the archived snapshot.
func buildTelemetryURL(ftpBaseURL, date string) string {
	if date == "" {
		return ftpBaseURL + "apnic/whois-rdap-stats/whois-rdap-stats.json"
	}
	return fmt.Sprintf("%s/apnic/whois-rdap-stats/%s/whois-rdap-stats-%s.json", ftpBaseURL, date[:4], date)
}

// buildTelemetrySidecarURL constructs the .md5 sidecar URL for the telemetry.
func buildTelemetrySidecarURL(ftpBaseURL, date string) string {
	return buildTelemetryURL(ftpBaseURL, date) + ".md5"
}

// buildIRRDBURL constructs the URL for an APNIC IRR database dump. objType is
// one of the IRRObjectTypes (e.g. "inetnum"). The dumps are gzip-compressed.
func buildIRRDBURL(ftpBaseURL, objType string) string {
	return fmt.Sprintf("%sapnic/whois/apnic.db.%s.gz", ftpBaseURL, objType)
}

// buildIRRCurrentSerialURL constructs the URL for the APNIC.CURRENTSERIAL file,
// which holds the current IRR database serial number.
func buildIRRCurrentSerialURL(ftpBaseURL string) string {
	return ftpBaseURL + "apnic/whois/APNIC.CURRENTSERIAL"
}

// buildThymeURL constructs the URL for an APNIC thyme BGP analysis file.
// source is one of "current", "au", or "hk"; an empty source defaults to
// "current" for backward compatibility. file is one of "data-summary",
// "data-raw-table", "data-badpfx-nos", "data-pfx-nos", "data-used-autnums",
// "data-spar", or "data-singlepfx".
func buildThymeURL(thymeBaseURL, source, file string) string {
	if source == "" {
		source = "current"
	}
	return strings.TrimRight(thymeBaseURL, "/") + "/" + source + "/" + file
}

// sourceOrDefault returns source if non-empty, else def. Used by thyme Fetch
// methods to let a per-call source override the client's default thymeSource.
func sourceOrDefault(source, def string) string {
	if source != "" {
		return source
	}
	return def
}

// buildRRDPNotificationURL constructs the URL for the RRDP notification file.
// The default rrdpBaseURL is https://rrdp.apnic.net.
func buildRRDPNotificationURL(rrdpBaseURL string) string {
	return strings.TrimRight(rrdpBaseURL, "/") + "/notification.xml"
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
