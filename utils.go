package apnic

import (
	"fmt"
	"strconv"
	"strings"
)

func parseIPv4Count(s string) (int64, error) {
	count, err := strconv.ParseInt(s, 10, 64)
	if err != nil || count <= 0 {
		return 0, fmt.Errorf("%w: %s", ErrInvalidIP, s)
	}
	return count, nil
}

func parseIPv6Prefix(s string) (int64, error) {
	prefix, err := strconv.ParseInt(s, 10, 64)
	if err != nil || prefix < 0 || prefix > 128 {
		return 0, fmt.Errorf("%w: %s", ErrInvalidIP, s)
	}
	return prefix, nil
}

func parseASNValue(s string) (int64, error) {
	if !strings.HasPrefix(s, "AS") {
		return 0, fmt.Errorf("%w: %s", ErrInvalidASN, s)
	}
	asn, err := strconv.ParseInt(s[2:], 10, 64)
	if err != nil || asn <= 0 {
		return 0, fmt.Errorf("%w: %s", ErrInvalidASN, s)
	}
	return asn, nil
}
