package apnic

import "time"

type DelegatedEntry struct {
	Registry   string
	Country    string
	Type       string
	Start      string
	Value      int64
	Date       time.Time
	Status     string
	Extensions []string
}

type WhoisInfo struct {
	Network     string
	CIDR        []string
	Country     string
	OrgName     string
	Parent      string
	Created     time.Time
	LastUpdated time.Time
}
