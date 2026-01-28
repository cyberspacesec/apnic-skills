package apnic

import (
	"fmt"
	"math"
)

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
