package apnic

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// RDAPLookupIP queries the RDAP service for an IP address.
// Returns structured information about the IP network including entities, status, and CIDR.
func (c *Client) RDAPLookupIP(ctx context.Context, ip string) (*RDAPNetwork, error) {
	var result RDAPNetwork
	err := c.doRDAPRequest(ctx, "/ip/"+ip, &result)
	if err != nil {
		return nil, fmt.Errorf("%w: IP lookup for %s: %v", ErrRDAPQueryFailed, ip, err)
	}
	return &result, nil
}

// RDAPLookupCIDR queries the RDAP service for a CIDR block.
// cidr should be in standard notation (e.g. "1.1.1.0/24").
func (c *Client) RDAPLookupCIDR(ctx context.Context, cidr string) (*RDAPNetwork, error) {
	var result RDAPNetwork
	err := c.doRDAPRequest(ctx, "/ip/"+cidr, &result)
	if err != nil {
		return nil, fmt.Errorf("%w: CIDR lookup for %s: %v", ErrRDAPQueryFailed, cidr, err)
	}
	return &result, nil
}

// RDAPLookupASN queries the RDAP service for an Autonomous System Number.
// asn should be a plain number (e.g. 13335), not "AS13335".
func (c *Client) RDAPLookupASN(ctx context.Context, asn int64) (*RDAPAutnum, error) {
	var result RDAPAutnum
	path := fmt.Sprintf("/autnum/%d", asn)
	err := c.doRDAPRequest(ctx, path, &result)
	if err != nil {
		return nil, fmt.Errorf("%w: ASN lookup for %d: %v", ErrRDAPQueryFailed, asn, err)
	}
	return &result, nil
}

// RDAPLookupDomain queries the RDAP service for a domain object.
// Typically used for reverse DNS domains (e.g. "1.0.0.1.in-addr.arpa").
func (c *Client) RDAPLookupDomain(ctx context.Context, domain string) (*RDAPDomain, error) {
	var result RDAPDomain
	err := c.doRDAPRequest(ctx, "/domain/"+domain, &result)
	if err != nil {
		return nil, fmt.Errorf("%w: domain lookup for %s: %v", ErrRDAPQueryFailed, domain, err)
	}
	return &result, nil
}

// RDAPLookupEntity queries the RDAP service for an entity (contact/organization).
// handle is the entity handle (e.g. "ORG-ARAD1-AP", "AIC3-AP").
func (c *Client) RDAPLookupEntity(ctx context.Context, handle string) (*RDAPEntity, error) {
	var result RDAPEntity
	err := c.doRDAPRequest(ctx, "/entity/"+handle, &result)
	if err != nil {
		return nil, fmt.Errorf("%w: entity lookup for %s: %v", ErrRDAPQueryFailed, handle, err)
	}
	return &result, nil
}

// RDAPSearch performs a full-text search against the RDAP database.
// query can be an IP address, CIDR, ASN, domain name, or entity handle.
func (c *Client) RDAPSearch(ctx context.Context, query string) (*RDAPSearchResult, error) {
	var result RDAPSearchResult
	path := "/search?query=" + query
	err := c.doRDAPRequest(ctx, path, &result)
	if err != nil {
		return nil, fmt.Errorf("%w: search for %s: %v", ErrRDAPQueryFailed, query, err)
	}
	return &result, nil
}

// doRDAPRequest performs a generic RDAP HTTP request and decodes the JSON response.
func (c *Client) doRDAPRequest(ctx context.Context, path string, result interface{}) error {
	url := c.rdapBaseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("request creation failed: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/rdap+json, application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response failed: %w", err)
	}

	// Check for RDAP error responses
	if resp.StatusCode == http.StatusNotFound {
		var rdapErr RDAPError
		if json.Unmarshal(body, &rdapErr) == nil {
			return fmt.Errorf("%w: %s", ErrNotFound, rdapErr.Title)
		}
		return ErrNotFound
	}

	if resp.StatusCode != http.StatusOK {
		var rdapErr RDAPError
		if json.Unmarshal(body, &rdapErr) == nil && rdapErr.Title != "" {
			return fmt.Errorf("RDAP error %d: %s", rdapErr.ErrorCode, rdapErr.Title)
		}
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	if err := json.Unmarshal(body, result); err != nil {
		return fmt.Errorf("JSON decode failed: %w", err)
	}

	return nil
}
