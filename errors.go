package apnic

import "errors"

var (
	ErrInvalidIP       = errors.New("invalid IP address")
	ErrInvalidASN      = errors.New("invalid ASN format")
	ErrUnsupportedType = errors.New("unsupported resource type")
	ErrWhoisTimeout    = errors.New("whois query timed out")
	ErrCacheExpired    = errors.New("cache expired")
)
