package apnic

import (
	"context"
	"net"
)

func (c *Client) ReverseDNS(ctx context.Context, ip string) ([]string, error) {
	resolver := net.Resolver{}
	return resolver.LookupAddr(ctx, ip)
}
