package apnic

import (
	"context"
	"crypto/md5"
	"fmt"
	"strings"
)

// VerifyMD5 verifies the MD5 checksum of a stats data file.
// dataType: "delegated", "delegated-extended", "assigned", "legacy"
// date: optional date in YYYYMMDD format; if empty, uses "latest"
func (c *Client) VerifyMD5(ctx context.Context, dataType, date string) error {
	// Fetch the data
	dataURL := buildStatsURL(c.statsBaseURL, dataType, date)
	data, err := c.fetchText(ctx, dataURL)
	if err != nil {
		return err
	}

	// Fetch the MD5 checksum
	md5URL := buildStatsMD5URL(c.statsBaseURL, dataType, date)
	expectedMD5, err := c.fetchText(ctx, md5URL)
	if err != nil {
		return err
	}

	// Parse the MD5 checksum file (format: "hash  filename")
	expectedMD5 = strings.TrimSpace(expectedMD5)
	parts := strings.Fields(expectedMD5)
	if len(parts) < 1 {
		return fmt.Errorf("%w: empty MD5 checksum file", ErrVerifyFailed)
	}
	expectedHash := parts[0]

	// Calculate the MD5 of the data
	hash := fmt.Sprintf("%x", md5.Sum([]byte(data)))

	if hash != expectedHash {
		return fmt.Errorf("%w: MD5 mismatch (expected %s, got %s)", ErrVerifyFailed, expectedHash, hash)
	}

	return nil
}

// FetchMD5Checksum fetches the MD5 checksum for a stats data file.
// dataType: "delegated", "delegated-extended", "assigned", "legacy"
// date: optional date in YYYYMMDD format; if empty, uses "latest"
func (c *Client) FetchMD5Checksum(ctx context.Context, dataType, date string) (string, error) {
	md5URL := buildStatsMD5URL(c.statsBaseURL, dataType, date)
	content, err := c.fetchText(ctx, md5URL)
	if err != nil {
		return "", err
	}

	// Parse the MD5 checksum file
	content = strings.TrimSpace(content)
	parts := strings.Fields(content)
	if len(parts) < 1 {
		return "", fmt.Errorf("%w: empty MD5 checksum file", ErrVerifyFailed)
	}
	return parts[0], nil
}

// FetchASCSignature fetches the ASC (PGP) signature for a stats data file.
// dataType: "delegated", "delegated-extended", "assigned", "legacy"
// date: optional date in YYYYMMDD format; if empty, uses "latest"
func (c *Client) FetchASCSignature(ctx context.Context, dataType, date string) (string, error) {
	ascURL := buildStatsASCURL(c.statsBaseURL, dataType, date)
	return c.fetchText(ctx, ascURL)
}

// FetchPublicKey fetches the current APNIC public key used for signing stats files.
func (c *Client) FetchPublicKey(ctx context.Context) (string, error) {
	url := c.statsBaseURL + "CURRENT_PUBLIC_KEY"
	return c.fetchText(ctx, url)
}
