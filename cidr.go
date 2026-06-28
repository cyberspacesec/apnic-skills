package apnic

import (
	"fmt"
	"math"
	"time"
)

// FilterEntries filters delegated entries by country and resource type.
func FilterEntries(entries []DelegatedEntry, country, resType string) []DelegatedEntry {
	result := make([]DelegatedEntry, 0, len(entries))
	for _, e := range entries {
		if (country == "" || e.Country == country) &&
			(resType == "" || e.Type == resType) {
			result = append(result, e)
		}
	}
	return result
}

// FilterByStatus filters delegated entries by status (allocated, assigned, reserved, available).
func FilterByStatus(entries []DelegatedEntry, status string) []DelegatedEntry {
	result := make([]DelegatedEntry, 0, len(entries))
	for _, e := range entries {
		if status == "" || e.Status == status {
			result = append(result, e)
		}
	}
	return result
}

// FilterByDateRange filters delegated entries by date range (inclusive).
func FilterByDateRange(entries []DelegatedEntry, start, end time.Time) []DelegatedEntry {
	result := make([]DelegatedEntry, 0, len(entries))
	for _, e := range entries {
		if !e.Date.IsZero() {
			if !start.IsZero() && e.Date.Before(start) {
				continue
			}
			if !end.IsZero() && e.Date.After(end) {
				continue
			}
			result = append(result, e)
		}
	}
	return result
}

// FilterExtendedByOpaqueID filters extended entries by opaque-id (organization identifier).
func FilterExtendedByOpaqueID(entries []DelegatedExtendedEntry, opaqueID string) []DelegatedExtendedEntry {
	result := make([]DelegatedExtendedEntry, 0, len(entries))
	for _, e := range entries {
		if opaqueID == "" || e.OpaqueID == opaqueID {
			result = append(result, e)
		}
	}
	return result
}

// FilterExtendedByCountry filters extended entries by country code.
func FilterExtendedByCountry(entries []DelegatedExtendedEntry, country string) []DelegatedExtendedEntry {
	result := make([]DelegatedExtendedEntry, 0, len(entries))
	for _, e := range entries {
		if country == "" || e.Country == country {
			result = append(result, e)
		}
	}
	return result
}

// FilterExtendedByType filters extended entries by resource type.
func FilterExtendedByType(entries []DelegatedExtendedEntry, resType string) []DelegatedExtendedEntry {
	result := make([]DelegatedExtendedEntry, 0, len(entries))
	for _, e := range entries {
		if resType == "" || e.Type == resType {
			result = append(result, e)
		}
	}
	return result
}

// FilterExtendedByStatus filters extended entries by status.
func FilterExtendedByStatus(entries []DelegatedExtendedEntry, status string) []DelegatedExtendedEntry {
	result := make([]DelegatedExtendedEntry, 0, len(entries))
	for _, e := range entries {
		if status == "" || e.Status == status {
			result = append(result, e)
		}
	}
	return result
}

// GroupByCountry groups delegated entries by country code.
func GroupByCountry(entries []DelegatedEntry) map[string][]DelegatedEntry {
	result := make(map[string][]DelegatedEntry)
	for _, e := range entries {
		result[e.Country] = append(result[e.Country], e)
	}
	return result
}

// GroupExtendedByOpaqueID groups extended entries by opaque-id (organization).
func GroupExtendedByOpaqueID(entries []DelegatedExtendedEntry) map[string][]DelegatedExtendedEntry {
	result := make(map[string][]DelegatedExtendedEntry)
	for _, e := range entries {
		result[e.OpaqueID] = append(result[e.OpaqueID], e)
	}
	return result
}

// GroupExtendedByCountry groups extended entries by country code.
func GroupExtendedByCountry(entries []DelegatedExtendedEntry) map[string][]DelegatedExtendedEntry {
	result := make(map[string][]DelegatedExtendedEntry)
	for _, e := range entries {
		result[e.Country] = append(result[e.Country], e)
	}
	return result
}

// CIDR converts a DelegatedEntry to CIDR notation.
func (e DelegatedEntry) CIDR() (string, error) {
	switch e.Type {
	case "ipv4":
		if e.Value <= 0 || e.Value > 1<<32 {
			return "", fmt.Errorf("%w: invalid IPv4 count %d", ErrInvalidIP, e.Value)
		}
		prefix := 32 - int(math.Log2(float64(e.Value)))
		return fmt.Sprintf("%s/%d", e.Start, prefix), nil
	case "ipv6":
		if e.Value < 0 || e.Value > 128 {
			return "", fmt.Errorf("%w: invalid IPv6 prefix %d", ErrInvalidIP, e.Value)
		}
		return fmt.Sprintf("%s/%d", e.Start, e.Value), nil
	default:
		return "", ErrUnsupportedType
	}
}

// CIDR converts a DelegatedExtendedEntry to CIDR notation.
func (e DelegatedExtendedEntry) CIDR() (string, error) {
	switch e.Type {
	case "ipv4":
		if e.Value <= 0 || e.Value > 1<<32 {
			return "", fmt.Errorf("%w: invalid IPv4 count %d", ErrInvalidIP, e.Value)
		}
		prefix := 32 - int(math.Log2(float64(e.Value)))
		return fmt.Sprintf("%s/%d", e.Start, prefix), nil
	case "ipv6":
		if e.Value < 0 || e.Value > 128 {
			return "", fmt.Errorf("%w: invalid IPv6 prefix %d", ErrInvalidIP, e.Value)
		}
		return fmt.Sprintf("%s/%d", e.Start, e.Value), nil
	default:
		return "", ErrUnsupportedType
	}
}

// CIDR converts a LegacyEntry to CIDR notation.
func (e LegacyEntry) CIDR() (string, error) {
	switch e.Type {
	case "ipv4":
		if e.Value <= 0 || e.Value > 1<<32 {
			return "", fmt.Errorf("%w: invalid IPv4 count %d", ErrInvalidIP, e.Value)
		}
		prefix := 32 - int(math.Log2(float64(e.Value)))
		return fmt.Sprintf("%s/%d", e.Start, prefix), nil
	case "ipv6":
		if e.Value < 0 || e.Value > 128 {
			return "", fmt.Errorf("%w: invalid IPv6 prefix %d", ErrInvalidIP, e.Value)
		}
		return fmt.Sprintf("%s/%d", e.Start, e.Value), nil
	default:
		return "", ErrUnsupportedType
	}
}
