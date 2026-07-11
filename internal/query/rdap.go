package query

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RDAPLookupIP queries the RDAP service for an IP address.
// Returns structured information about the IP network including entities, status, and CIDR.
// If a point-in-time date was set via WithRDAPDate, the historical state is returned.
func (c *Client) RDAPLookupIP(ctx context.Context, ip string) (*RDAPNetwork, error) {
	return c.rdapLookupIPAt(ctx, ip, time.Time{})
}

// RDAPLookupIPAt queries the RDAP service for an IP address as it was at the given
// UTC instant (point-in-time / history_version_0). A zero time returns the live state.
func (c *Client) RDAPLookupIPAt(ctx context.Context, ip string, date time.Time) (*RDAPNetwork, error) {
	return c.rdapLookupIPAt(ctx, ip, date)
}

func (c *Client) rdapLookupIPAt(ctx context.Context, ip string, date time.Time) (*RDAPNetwork, error) {
	var result RDAPNetwork
	err := c.doRDAPRequestAt(ctx, "/ip/"+ip, &result, date)
	if err != nil {
		return nil, fmt.Errorf("%w: IP lookup for %s: %v", ErrRDAPQueryFailed, ip, err)
	}
	return &result, nil
}

// RDAPLookupCIDR queries the RDAP service for a CIDR block.
// cidr should be in standard notation (e.g. "1.1.1.0/24").
func (c *Client) RDAPLookupCIDR(ctx context.Context, cidr string) (*RDAPNetwork, error) {
	return c.RDAPLookupCIDRAt(ctx, cidr, time.Time{})
}

// RDAPLookupCIDRAt queries the RDAP service for a CIDR block as it was at the given
// UTC instant (point-in-time). A zero time returns the live state.
func (c *Client) RDAPLookupCIDRAt(ctx context.Context, cidr string, date time.Time) (*RDAPNetwork, error) {
	var result RDAPNetwork
	err := c.doRDAPRequestAt(ctx, "/ip/"+cidr, &result, date)
	if err != nil {
		return nil, fmt.Errorf("%w: CIDR lookup for %s: %v", ErrRDAPQueryFailed, cidr, err)
	}
	return &result, nil
}

// RDAPLookupASN queries the RDAP service for an Autonomous System Number.
// asn should be a plain number (e.g. 13335), not "AS13335".
func (c *Client) RDAPLookupASN(ctx context.Context, asn int64) (*RDAPAutnum, error) {
	return c.RDAPLookupASNAt(ctx, asn, time.Time{})
}

// RDAPLookupASNAt queries the RDAP service for an ASN as it was at the given
// UTC instant (point-in-time). A zero time returns the live state.
func (c *Client) RDAPLookupASNAt(ctx context.Context, asn int64, date time.Time) (*RDAPAutnum, error) {
	var result RDAPAutnum
	path := fmt.Sprintf("/autnum/%d", asn)
	err := c.doRDAPRequestAt(ctx, path, &result, date)
	if err != nil {
		return nil, fmt.Errorf("%w: ASN lookup for %d: %v", ErrRDAPQueryFailed, asn, err)
	}
	return &result, nil
}

// RDAPLookupDomain queries the RDAP service for a domain object.
// Typically used for reverse DNS domains (e.g. "1.0.0.1.in-addr.arpa").
func (c *Client) RDAPLookupDomain(ctx context.Context, domain string) (*RDAPDomain, error) {
	return c.RDAPLookupDomainAt(ctx, domain, time.Time{})
}

// RDAPLookupDomainAt queries the RDAP service for a domain object as it was at the
// given UTC instant (point-in-time). A zero time returns the live state.
func (c *Client) RDAPLookupDomainAt(ctx context.Context, domain string, date time.Time) (*RDAPDomain, error) {
	var result RDAPDomain
	err := c.doRDAPRequestAt(ctx, "/domain/"+domain, &result, date)
	if err != nil {
		return nil, fmt.Errorf("%w: domain lookup for %s: %v", ErrRDAPQueryFailed, domain, err)
	}
	return &result, nil
}

// RDAPLookupEntity queries the RDAP service for an entity (contact/organization).
// handle is the entity handle (e.g. "ORG-ARAD1-AP", "AIC3-AP").
func (c *Client) RDAPLookupEntity(ctx context.Context, handle string) (*RDAPEntity, error) {
	return c.RDAPLookupEntityAt(ctx, handle, time.Time{})
}

// RDAPLookupEntityAt queries the RDAP service for an entity as it was at the given
// UTC instant (point-in-time). A zero time returns the live state.
func (c *Client) RDAPLookupEntityAt(ctx context.Context, handle string, date time.Time) (*RDAPEntity, error) {
	var result RDAPEntity
	err := c.doRDAPRequestAt(ctx, "/entity/"+handle, &result, date)
	if err != nil {
		return nil, fmt.Errorf("%w: entity lookup for %s: %v", ErrRDAPQueryFailed, handle, err)
	}
	return &result, nil
}

// RDAPSearch performs an entity name search against the APNIC RDAP database.
// APNIC does not provide a generic /search endpoint; search is performed via the
// RFC 7482 /entities endpoint using the "fn" (friendly name) query parameter.
// The query is matched against entity names; APNIC requires wildcard characters
// (e.g. "*CLOUD*") for substring matches — an exact name with no wildcard only
// matches an entity whose name is exactly that string.
// This is a convenience wrapper around RDAPSearchEntities with the "fn" field.
// For handle-based exact lookups, use RDAPLookupEntity instead.
func (c *Client) RDAPSearch(ctx context.Context, query string) (*RDAPSearchResult, error) {
	return c.RDAPSearchEntities(ctx, "fn", query)
}

// RDAPSearchEntities searches the APNIC RDAP entity database.
// field selects the search criterion: "fn" (fuzzy name match, supports "*"
// wildcards) or "handle" (exact entity handle match).
// Returns matching entities in EntitySearchResults.
func (c *Client) RDAPSearchEntities(ctx context.Context, field, query string) (*RDAPSearchResult, error) {
	if field != "fn" && field != "handle" {
		return nil, fmt.Errorf("%w: unsupported search field %q (use fn or handle)", ErrRDAPQueryFailed, field)
	}
	if query == "" {
		return nil, fmt.Errorf("%w: empty search query", ErrRDAPQueryFailed)
	}

	var result RDAPSearchResult
	path := fmt.Sprintf("/entities?%s=%s", field, url.QueryEscape(query))
	err := c.doRDAPRequestAt(ctx, path, &result, time.Time{})
	if err != nil {
		return nil, fmt.Errorf("%w: entity search (%s=%s): %v", ErrRDAPQueryFailed, field, query, err)
	}
	return &result, nil
}

// RDAPHelp queries the RDAP /help endpoint (RFC 7483), returning the server's
// capability description: rdapConformance extensions (e.g. history_version_0,
// cidr0, nro_rdap_profile_0), notices (terms of service, inaccuracy reporting),
// and port43. Useful for discovering which extensions the server supports.
func (c *Client) RDAPHelp(ctx context.Context) (*RDAPHelpInfo, error) {
	var result RDAPHelpInfo
	err := c.doRDAPRequestAt(ctx, "/help", &result, time.Time{})
	if err != nil {
		return nil, fmt.Errorf("%w: help: %v", ErrRDAPQueryFailed, err)
	}
	return &result, nil
}

// RDAPSearchDomains searches the APNIC RDAP database for reverse-DNS domain
// objects by name (RFC 7482 /domains?name=). Returns matching domains in
// DomainSearchResults. This is the domain analogue of RDAPSearchEntities.
func (c *Client) RDAPSearchDomains(ctx context.Context, name string) (*RDAPDomainSearchResult, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: empty domain search query", ErrRDAPQueryFailed)
	}
	var result RDAPDomainSearchResult
	path := "/domains?name=" + url.QueryEscape(name)
	err := c.doRDAPRequestAt(ctx, path, &result, time.Time{})
	if err != nil {
		return nil, fmt.Errorf("%w: domain search (name=%s): %v", ErrRDAPQueryFailed, name, err)
	}
	return &result, nil
}

// doRDAPRequestAt performs a generic RDAP HTTP GET and decodes the JSON response.
// A non-zero date overrides the client default and adds a "date" query parameter
// for a point-in-time (history_version_0) lookup. A zero date falls back to the
// client's rdapDate, or a live query if that is also zero.
func (c *Client) doRDAPRequestAt(ctx context.Context, path string, result interface{}, date time.Time) error {
	effectiveDate := date
	if effectiveDate.IsZero() {
		effectiveDate = c.rdapDate
	}
	if !effectiveDate.IsZero() {
		sep := "&"
		if !strings.Contains(path, "?") {
			sep = "?"
		}
		path = path + sep + "date=" + url.QueryEscape(effectiveDate.UTC().Format(time.RFC3339))
	}

	url := c.rdapBaseURL + path

	resp, err := c.doHTTPRequest(ctx, "GET", url, "application/rdap+json, application/json")
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
