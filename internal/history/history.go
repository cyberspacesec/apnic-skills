package history

import (
	"context"
	"fmt"
)

// FetchHistoricalDelegated fetches delegated stats for a specific date.
// date must be in YYYYMMDD format.
func (c *Client) FetchHistoricalDelegated(ctx context.Context, date string) (*DelegatedResult, error) {
	if len(date) != 8 {
		return nil, fmt.Errorf("%w: date must be in YYYYMMDD format, got %s", ErrInvalidDate, date)
	}
	return c.FetchDelegatedResult(ctx, date)
}

// FetchHistoricalExtended fetches extended delegated stats for a specific date.
// date must be in YYYYMMDD format.
func (c *Client) FetchHistoricalExtended(ctx context.Context, date string) (*ExtendedResult, error) {
	if len(date) != 8 {
		return nil, fmt.Errorf("%w: date must be in YYYYMMDD format, got %s", ErrInvalidDate, date)
	}
	return c.FetchExtendedResult(ctx, date)
}

// FetchHistoricalAssigned fetches assigned stats for a specific date.
// date must be in YYYYMMDD format.
func (c *Client) FetchHistoricalAssigned(ctx context.Context, date string) (*AssignedResult, error) {
	if len(date) != 8 {
		return nil, fmt.Errorf("%w: date must be in YYYYMMDD format, got %s", ErrInvalidDate, date)
	}
	return c.FetchAssignedResult(ctx, date)
}

// FetchHistoricalLegacy fetches legacy stats for a specific date.
// date must be in YYYYMMDD format.
func (c *Client) FetchHistoricalLegacy(ctx context.Context, date string) (*LegacyResult, error) {
	if len(date) != 8 {
		return nil, fmt.Errorf("%w: date must be in YYYYMMDD format, got %s", ErrInvalidDate, date)
	}
	return c.FetchLegacyResult(ctx, date)
}

// FetchDelegatedByYear fetches the delegated stats for the last day of the given year.
// year must be a valid year (2001 or later, as APNIC stats start from 2001).
// The file is served from the {year}/ archive subdirectory as a gzip-compressed file.
func (c *Client) FetchDelegatedByYear(ctx context.Context, year int) (*DelegatedResult, error) {
	if year < 2001 {
		return nil, fmt.Errorf("%w: year must be 2001 or later, got %d", ErrInvalidYear, year)
	}
	url := fmt.Sprintf("%s%d/delegated-apnic-%d1231.gz", c.statsBaseURL, year, year)
	body, err := c.fetchTextStr(ctx, url)
	if err != nil {
		return nil, err
	}
	return parseDelegatedFullFromString(body)
}

// FetchExtendedByYear fetches the extended delegated stats for the last day of the given year.
// The file is served from the {year}/ archive subdirectory as a gzip-compressed file.
func (c *Client) FetchExtendedByYear(ctx context.Context, year int) (*ExtendedResult, error) {
	if year < 2001 {
		return nil, fmt.Errorf("%w: year must be 2001 or later, got %d", ErrInvalidYear, year)
	}
	url := fmt.Sprintf("%s%d/delegated-apnic-extended-%d1231.gz", c.statsBaseURL, year, year)
	body, err := c.fetchTextStr(ctx, url)
	if err != nil {
		return nil, err
	}
	return parseExtendedFullFromString(body)
}

// ListAvailableYears returns the list of years for which historical data is available.
// APNIC provides stats data from 2001 onwards.
func ListAvailableYears() []int {
	currentYear := 2026 // Updated periodically; APNIC stats available from 2001
	years := make([]int, 0, currentYear-2001+1)
	for y := 2001; y <= currentYear; y++ {
		years = append(years, y)
	}
	return years
}
