package apnic

import (
	"testing"
	"time"
)

func TestParseIPv4Count(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
		hasErr   bool
	}{
		{"256", 256, false},
		{"512", 512, false},
		{"1024", 1024, false},
		{"65536", 65536, false},
		{"0", 0, true},
		{"-1", 0, true},
		{"abc", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		val, err := parseIPv4Count(tt.input)
		if tt.hasErr {
			if err == nil {
				t.Errorf("parseIPv4Count(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("parseIPv4Count(%q) unexpected error: %v", tt.input, err)
			}
			if val != tt.expected {
				t.Errorf("parseIPv4Count(%q) = %d, want %d", tt.input, val, tt.expected)
			}
		}
	}
}

func TestParseIPv6Prefix(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
		hasErr   bool
	}{
		{"32", 32, false},
		{"48", 48, false},
		{"64", 64, false},
		{"128", 128, false},
		{"0", 0, false},
		{"129", 0, true},
		{"-1", 0, true},
		{"abc", 0, true},
	}

	for _, tt := range tests {
		val, err := parseIPv6Prefix(tt.input)
		if tt.hasErr {
			if err == nil {
				t.Errorf("parseIPv6Prefix(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("parseIPv6Prefix(%q) unexpected error: %v", tt.input, err)
			}
			if val != tt.expected {
				t.Errorf("parseIPv6Prefix(%q) = %d, want %d", tt.input, val, tt.expected)
			}
		}
	}
}

func TestParseASNValue(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
		hasErr   bool
	}{
		{"173", 173, false},
		{"13335", 13335, false},
		{"0", 0, false},
		{"-1", 0, true},
		{"abc", 0, true},
	}

	for _, tt := range tests {
		val, err := parseASNValue(tt.input)
		if tt.hasErr {
			if err == nil {
				t.Errorf("parseASNValue(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("parseASNValue(%q) unexpected error: %v", tt.input, err)
			}
			if val != tt.expected {
				t.Errorf("parseASNValue(%q) = %d, want %d", tt.input, val, tt.expected)
			}
		}
	}
}

func TestParseASNCount(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
		hasErr   bool
	}{
		{"1", 1, false},
		{"10", 10, false},
		{"0", 0, true},
		{"-1", 0, true},
		{"abc", 0, true},
	}

	for _, tt := range tests {
		val, err := parseASNCount(tt.input)
		if tt.hasErr {
			if err == nil {
				t.Errorf("parseASNCount(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("parseASNCount(%q) unexpected error: %v", tt.input, err)
			}
			if val != tt.expected {
				t.Errorf("parseASNCount(%q) = %d, want %d", tt.input, val, tt.expected)
			}
		}
	}
}

func TestParseStatsHeader(t *testing.T) {
	tests := []struct {
		input    string
		version  string
		registry string
		records  int64
		hasErr   bool
	}{
		{"2|apnic|20260627|88485|19830613|20260626|+1000", "2", "apnic", 88485, false},
		{"2.3|apnic|20260627|188309||20260626|+1000", "2.3", "apnic", 188309, false},
		{"short|line", "", "", 0, true},
	}

	for _, tt := range tests {
		header, err := parseStatsHeader(tt.input)
		if tt.hasErr {
			if err == nil {
				t.Errorf("parseStatsHeader(%q) expected error", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("parseStatsHeader(%q) unexpected error: %v", tt.input, err)
			}
			if header.Version != tt.version {
				t.Errorf("version = %q, want %q", header.Version, tt.version)
			}
			if header.Registry != tt.registry {
				t.Errorf("registry = %q, want %q", header.Registry, tt.registry)
			}
			if header.Records != tt.records {
				t.Errorf("records = %d, want %d", header.Records, tt.records)
			}
		}
	}
}

func TestParseSummaryLine(t *testing.T) {
	tests := []struct {
		input    string
		registry string
		rtype    string
		count    int64
		hasErr   bool
	}{
		{"apnic|*|asn|*|14586|summary", "apnic", "asn", 14586, false},
		{"apnic|*|ipv4|*|61248|summary", "apnic", "ipv4", 61248, false},
		{"apnic|*|ipv6|*|16949|summary", "apnic", "ipv6", 16949, false},
		{"not|a|summary|line", "", "", 0, true},
		{"apnic|*|asn|*|100|notsummary", "", "", 0, true},
	}

	for _, tt := range tests {
		summary, err := parseSummaryLine(tt.input)
		if tt.hasErr {
			if err == nil {
				t.Errorf("parseSummaryLine(%q) expected error", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("parseSummaryLine(%q) unexpected error: %v", tt.input, err)
			}
			if summary.Registry != tt.registry {
				t.Errorf("registry = %q, want %q", summary.Registry, tt.registry)
			}
			if summary.Type != tt.rtype {
				t.Errorf("type = %q, want %q", summary.Type, tt.rtype)
			}
			if summary.Count != tt.count {
				t.Errorf("count = %d, want %d", summary.Count, tt.count)
			}
		}
	}
}

func TestIsHeaderLine(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		{"2|apnic|20260627|88485|19830613|20260626|+1000", true},
		{"2.3|apnic|20260627|188309||20260626|+1000", true},
		{"apnic|AU|ipv4|1.0.0.0|256|20110811|assigned", false},
		{"short", false},
	}

	for _, tt := range tests {
		result := isHeaderLine(tt.input)
		if result != tt.expect {
			t.Errorf("isHeaderLine(%q) = %v, want %v", tt.input, result, tt.expect)
		}
	}
}

func TestIsSummaryLine(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		{"apnic|*|asn|*|14586|summary", true},
		{"apnic|AU|ipv4|1.0.0.0|256|20110811|assigned", false},
	}

	for _, tt := range tests {
		result := isSummaryLine(tt.input)
		if result != tt.expect {
			t.Errorf("isSummaryLine(%q) = %v, want %v", tt.input, result, tt.expect)
		}
	}
}

func TestBuildStatsURL(t *testing.T) {
	base := "https://ftp.apnic.net/apnic/stats/apnic/"
	tests := []struct {
		dataType string
		date     string
		expected string
	}{
		{"delegated", "", base + "delegated-apnic-latest"},
		{"delegated", "20260627", base + "delegated-apnic-20260627"},
		{"delegated-extended", "", base + "delegated-extended-apnic-latest"},
		{"assigned", "20260101", base + "assigned-apnic-20260101"},
		{"legacy", "", base + "legacy-apnic-latest"},
	}

	for _, tt := range tests {
		result := buildStatsURL(base, tt.dataType, tt.date)
		if result != tt.expected {
			t.Errorf("buildStatsURL(%q, %q, %q) = %q, want %q", base, tt.dataType, tt.date, result, tt.expected)
		}
	}
}

func TestBuildStatsMD5URL(t *testing.T) {
	base := "https://ftp.apnic.net/apnic/stats/apnic/"
	result := buildStatsMD5URL(base, "delegated", "")
	expected := base + "delegated-apnic-latest.md5"
	if result != expected {
		t.Errorf("buildStatsMD5URL() = %q, want %q", result, expected)
	}
}

func TestBuildStatsASCURL(t *testing.T) {
	base := "https://ftp.apnic.net/apnic/stats/apnic/"
	result := buildStatsASCURL(base, "delegated", "")
	expected := base + "delegated-apnic-latest.asc"
	if result != expected {
		t.Errorf("buildStatsASCURL() = %q, want %q", result, expected)
	}
}

func TestParseOpaqueID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"A91872ED", "A91872ED"},
		{"  A91872ED  ", "A91872ED"},
		{"", ""},
	}

	for _, tt := range tests {
		result := parseOpaqueID(tt.input)
		if result != tt.expected {
			t.Errorf("parseOpaqueID(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestParseStatsDate(t *testing.T) {
	tests := []struct {
		input    string
		hasErr   bool
		isEmpty  bool
	}{
		{"20110811", false, false},
		{"20260627", false, false},
		{"00000000", false, true},
		{"", false, true},
		{"invalid", true, false},
	}

	for _, tt := range tests {
		tm, err := parseStatsDate(tt.input)
		if tt.hasErr {
			if err == nil {
				t.Errorf("parseStatsDate(%q) expected error", tt.input)
			}
		} else if err != nil {
			t.Errorf("parseStatsDate(%q) unexpected error: %v", tt.input, err)
		}
		if tt.isEmpty && !tm.IsZero() {
			t.Errorf("parseStatsDate(%q) expected zero time", tt.input)
		}
	}
}

func TestFormatDate(t *testing.T) {
	tm := time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)
	result := FormatDate(tm)
	if result != "20260627" {
		t.Errorf("FormatDate() = %q, want %q", result, "20260627")
	}
}

func TestParseDate(t *testing.T) {
	tm, err := ParseDate("20260627")
	if err != nil {
		t.Fatalf("ParseDate() error: %v", err)
	}
	if tm.Year() != 2026 || tm.Month() != 6 || tm.Day() != 27 {
		t.Errorf("ParseDate() = %v, want 2026-06-27", tm)
	}
}
