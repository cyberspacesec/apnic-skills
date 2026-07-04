package apnic

import (
	"bufio"
	"context"
	"fmt"
	"strings"
)

// FetchBGPSummary fetches and parses APNIC thyme's data-summary file, a
// colon-separated key/value listing of BGP routing table analysis metrics.
func (c *Client) FetchBGPSummary(ctx context.Context) (*BGPSummary, error) {
	url := buildThymeURL(c.thymeBaseURL, c.thymeSource, "data-summary")
	body, err := c.fetchText(ctx, url)
	if err != nil {
		return nil, err
	}
	return parseBGPSummary(body), nil
}

// FetchBGPRawTable fetches and parses APNIC thyme's data-raw-table file, which
// lists every BGP route as a "prefix\tASN" line.
func (c *Client) FetchBGPRawTable(ctx context.Context) (*BGPRawTable, error) {
	url := buildThymeURL(c.thymeBaseURL, c.thymeSource, "data-raw-table")
	body, err := c.fetchTextStr(ctx, url)
	if err != nil {
		return nil, err
	}
	t, err := parseBGPRawTable(body)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// FetchBGPASNMap fetches the raw BGP table and aggregates it by origin ASN,
// returning a map from each origin ASN to the prefixes it announces. This is a
// client-side derivation from data-raw-table; thyme does not publish a separate
// per-ASN file.
func (c *Client) FetchBGPASNMap(ctx context.Context) (*BGPASNMap, error) {
	raw, err := c.FetchBGPRawTable(ctx)
	if err != nil {
		return nil, err
	}
	m := &BGPASNMap{ASNs: make(map[string][]string, len(raw.Routes))}
	for _, r := range raw.Routes {
		m.ASNs[r.ASN] = append(m.ASNs[r.ASN], r.Prefix)
	}
	return m, nil
}

// parseBGPSummary parses the thyme data-summary file. Lines without a colon are
// skipped (including the "Analysis Summary" title and the dash separator). The
// key is the trimmed text before the first colon; the value is the trimmed text
// after it. Indented sub-metrics (which also use "key: value" form) are
// captured as their own entries.
func parseBGPSummary(data string) *BGPSummary {
	s := &BGPSummary{Entries: make([]BGPKeyValue, 0, 64)}
	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])
		if key == "" {
			continue
		}
		s.Entries = append(s.Entries, BGPKeyValue{Key: key, Value: val})
	}
	return s
}

// parseBGPRawTable parses the thyme data-raw-table file. Each non-empty line is
// a "prefix\tASN" pair. Lines that do not split into exactly two fields are
// skipped defensively.
func parseBGPRawTable(data string) (*BGPRawTable, error) {
	t := &BGPRawTable{Routes: make([]BGPRoute, 0, 1000000)}
	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // large default for big files
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		// thyme separates prefix and ASN with a tab.
		fields := strings.Split(line, "\t")
		if len(fields) != 2 {
			// Fall back to any-whitespace split for robustness.
			fields = strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
		}
		t.Routes = append(t.Routes, BGPRoute{Prefix: fields[0], ASN: fields[1]})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("BGP raw table scan failed: %w", err)
	}
	return t, nil
}
