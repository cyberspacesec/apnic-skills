package apnic

import (
	"testing"
	"time"
)

func TestFilterEntries(t *testing.T) {
	entries := []DelegatedEntry{
		{Country: "CN", Type: "ipv4", Start: "1.0.1.0", Value: 256, Status: "allocated"},
		{Country: "AU", Type: "ipv4", Start: "1.0.0.0", Value: 256, Status: "assigned"},
		{Country: "CN", Type: "ipv6", Start: "2001:240::", Value: 32, Status: "allocated"},
		{Country: "JP", Type: "asn", Start: "173", Value: 1, Status: "allocated"},
	}

	cn := FilterEntries(entries, "CN", "")
	if len(cn) != 2 {
		t.Errorf("CN entries = %d, want 2", len(cn))
	}

	ipv4 := FilterEntries(entries, "", "ipv4")
	if len(ipv4) != 2 {
		t.Errorf("ipv4 entries = %d, want 2", len(ipv4))
	}

	cnIPv4 := FilterEntries(entries, "CN", "ipv4")
	if len(cnIPv4) != 1 {
		t.Errorf("CN ipv4 entries = %d, want 1", len(cnIPv4))
	}

	all := FilterEntries(entries, "", "")
	if len(all) != 4 {
		t.Errorf("all entries = %d, want 4", len(all))
	}
}

func TestFilterByStatus(t *testing.T) {
	entries := []DelegatedEntry{
		{Country: "CN", Type: "ipv4", Status: "allocated"},
		{Country: "AU", Type: "ipv4", Status: "assigned"},
		{Country: "JP", Type: "ipv4", Status: "allocated"},
	}

	allocated := FilterByStatus(entries, "allocated")
	if len(allocated) != 2 {
		t.Errorf("allocated entries = %d, want 2", len(allocated))
	}

	assigned := FilterByStatus(entries, "assigned")
	if len(assigned) != 1 {
		t.Errorf("assigned entries = %d, want 1", len(assigned))
	}

	all := FilterByStatus(entries, "")
	if len(all) != 3 {
		t.Errorf("all entries = %d, want 3", len(all))
	}
}

func TestFilterByDateRange(t *testing.T) {
	entries := []DelegatedEntry{
		{Country: "AU", Date: time.Date(2011, 8, 11, 0, 0, 0, 0, time.UTC)},
		{Country: "CN", Date: time.Date(2011, 4, 14, 0, 0, 0, 0, time.UTC)},
		{Country: "JP", Date: time.Date(2002, 8, 1, 0, 0, 0, 0, time.UTC)},
		{Country: "US", Date: time.Time{}}, // zero date
		{Country: "UK", Date: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)}, // after end
	}

	start := time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC)

	filtered := FilterByDateRange(entries, start, end)
	if len(filtered) != 2 {
		t.Errorf("filtered entries = %d, want 2", len(filtered))
	}

	// Only start
	filteredStart := FilterByDateRange(entries, start, time.Time{})
	if len(filteredStart) != 3 {
		t.Errorf("filtered by start = %d, want 3", len(filteredStart))
	}

	// Only end
	filteredEnd := FilterByDateRange(entries, time.Time{}, end)
	if len(filteredEnd) != 3 {
		t.Errorf("filtered by end = %d, want 3", len(filteredEnd))
	}

	// Both zero - should include all non-zero dates
	filteredBoth := FilterByDateRange(entries, time.Time{}, time.Time{})
	if len(filteredBoth) != 4 {
		t.Errorf("filtered by both zero = %d, want 4", len(filteredBoth))
	}
}

func TestFilterExtendedByOpaqueID(t *testing.T) {
	entries := []DelegatedExtendedEntry{
		{OpaqueID: "A91872ED", Country: "AU"},
		{OpaqueID: "A92E1062", Country: "CN"},
		{OpaqueID: "A92E1062", Country: "CN"},
	}

	filtered := FilterExtendedByOpaqueID(entries, "A92E1062")
	if len(filtered) != 2 {
		t.Errorf("filtered = %d, want 2", len(filtered))
	}

	all := FilterExtendedByOpaqueID(entries, "")
	if len(all) != 3 {
		t.Errorf("all = %d, want 3", len(all))
	}
}

func TestFilterExtendedByCountry(t *testing.T) {
	entries := []DelegatedExtendedEntry{
		{Country: "AU"},
		{Country: "CN"},
		{Country: "CN"},
	}

	filtered := FilterExtendedByCountry(entries, "CN")
	if len(filtered) != 2 {
		t.Errorf("filtered = %d, want 2", len(filtered))
	}
}

func TestFilterExtendedByType(t *testing.T) {
	entries := []DelegatedExtendedEntry{
		{Type: "ipv4"},
		{Type: "ipv6"},
		{Type: "ipv4"},
	}

	filtered := FilterExtendedByType(entries, "ipv4")
	if len(filtered) != 2 {
		t.Errorf("filtered = %d, want 2", len(filtered))
	}
}

func TestFilterExtendedByStatus(t *testing.T) {
	entries := []DelegatedExtendedEntry{
		{Status: "allocated"},
		{Status: "assigned"},
		{Status: "allocated"},
	}

	filtered := FilterExtendedByStatus(entries, "allocated")
	if len(filtered) != 2 {
		t.Errorf("filtered = %d, want 2", len(filtered))
	}
}

func TestGroupByCountry(t *testing.T) {
	entries := []DelegatedEntry{
		{Country: "CN"},
		{Country: "AU"},
		{Country: "CN"},
	}

	grouped := GroupByCountry(entries)
	if len(grouped["CN"]) != 2 {
		t.Errorf("CN count = %d, want 2", len(grouped["CN"]))
	}
	if len(grouped["AU"]) != 1 {
		t.Errorf("AU count = %d, want 1", len(grouped["AU"]))
	}
}

func TestGroupExtendedByOpaqueID(t *testing.T) {
	entries := []DelegatedExtendedEntry{
		{OpaqueID: "A1"},
		{OpaqueID: "A2"},
		{OpaqueID: "A1"},
	}

	grouped := GroupExtendedByOpaqueID(entries)
	if len(grouped["A1"]) != 2 {
		t.Errorf("A1 count = %d, want 2", len(grouped["A1"]))
	}
}

func TestGroupExtendedByCountry(t *testing.T) {
	entries := []DelegatedExtendedEntry{
		{Country: "CN"},
		{Country: "JP"},
		{Country: "CN"},
	}

	grouped := GroupExtendedByCountry(entries)
	if len(grouped["CN"]) != 2 {
		t.Errorf("CN count = %d, want 2", len(grouped["CN"]))
	}
}

func TestDelegatedEntryCIDR(t *testing.T) {
	tests := []struct {
		entry    DelegatedEntry
		expected string
		hasErr   bool
	}{
		{DelegatedEntry{Type: "ipv4", Start: "1.1.1.0", Value: 256}, "1.1.1.0/24", false},
		{DelegatedEntry{Type: "ipv4", Start: "1.0.0.0", Value: 1024}, "1.0.0.0/22", false},
		{DelegatedEntry{Type: "ipv6", Start: "2001:240::", Value: 32}, "2001:240::/32", false},
		{DelegatedEntry{Type: "ipv4", Start: "1.0.0.0", Value: 0}, "", true},
		{DelegatedEntry{Type: "ipv4", Start: "1.0.0.0", Value: int64(1) << 33}, "", true},
		{DelegatedEntry{Type: "ipv6", Start: "2001::", Value: -1}, "", true},
		{DelegatedEntry{Type: "ipv6", Start: "2001::", Value: 129}, "", true},
		{DelegatedEntry{Type: "asn", Start: "13335"}, "", true},
		{DelegatedEntry{Type: "ipv4", Start: "10.0.0.0", Value: 1}, "10.0.0.0/32", false},
	}

	for _, tt := range tests {
		result, err := tt.entry.CIDR()
		if tt.hasErr {
			if err == nil {
				t.Errorf("CIDR() expected error for %+v", tt.entry)
			}
		} else {
			if err != nil {
				t.Errorf("CIDR() unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("CIDR() = %q, want %q", result, tt.expected)
			}
		}
	}
}

func TestDelegatedExtendedEntryCIDR(t *testing.T) {
	entry := DelegatedExtendedEntry{Type: "ipv4", Start: "1.1.1.0", Value: 256}
	cidr, err := entry.CIDR()
	if err != nil {
		t.Fatalf("CIDR() error: %v", err)
	}
	if cidr != "1.1.1.0/24" {
		t.Errorf("CIDR() = %q, want 1.1.1.0/24", cidr)
	}

	// Test IPv6 success path
	entry6 := DelegatedExtendedEntry{Type: "ipv6", Start: "2001:240::", Value: 32}
	cidr6, err := entry6.CIDR()
	if err != nil {
		t.Fatalf("CIDR() IPv6 error: %v", err)
	}
	if cidr6 != "2001:240::/32" {
		t.Errorf("CIDR() IPv6 = %q, want 2001:240::/32", cidr6)
	}
}

func TestLegacyEntryCIDR(t *testing.T) {
	entry := LegacyEntry{Type: "ipv4", Start: "128.134.0.0", Value: 65536}
	cidr, err := entry.CIDR()
	if err != nil {
		t.Fatalf("CIDR() error: %v", err)
	}
	if cidr != "128.134.0.0/16" {
		t.Errorf("CIDR() = %q, want 128.134.0.0/16", cidr)
	}

	// Test IPv6 success path
	entry6 := LegacyEntry{Type: "ipv6", Start: "2001:db8::", Value: 48}
	cidr6, err := entry6.CIDR()
	if err != nil {
		t.Fatalf("CIDR() IPv6 error: %v", err)
	}
	if cidr6 != "2001:db8::/48" {
		t.Errorf("CIDR() IPv6 = %q, want 2001:db8::/48", cidr6)
	}
}

func TestExtendedEntryCIDRErrors(t *testing.T) {
	tests := []struct {
		entry  DelegatedExtendedEntry
		hasErr bool
	}{
		{DelegatedExtendedEntry{Type: "ipv4", Value: 0}, true},
		{DelegatedExtendedEntry{Type: "ipv4", Value: int64(1) << 33}, true},
		{DelegatedExtendedEntry{Type: "ipv6", Value: -1}, true},
		{DelegatedExtendedEntry{Type: "ipv6", Value: 129}, true},
		{DelegatedExtendedEntry{Type: "asn"}, true},
	}

	for i, tt := range tests {
		_, err := tt.entry.CIDR()
		if tt.hasErr && err == nil {
			t.Errorf("test %d: expected error", i)
		}
	}
}

func TestLegacyEntryCIDRErrors(t *testing.T) {
	tests := []struct {
		entry  LegacyEntry
		hasErr bool
	}{
		{LegacyEntry{Type: "ipv4", Value: 0}, true},
		{LegacyEntry{Type: "ipv4", Value: int64(1) << 33}, true},
		{LegacyEntry{Type: "ipv6", Value: -1}, true},
		{LegacyEntry{Type: "ipv6", Value: 129}, true},
		{LegacyEntry{Type: "asn"}, true},
	}

	for i, tt := range tests {
		_, err := tt.entry.CIDR()
		if tt.hasErr && err == nil {
			t.Errorf("test %d: expected error", i)
		}
	}
}
