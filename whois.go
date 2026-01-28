package apnic

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

func (c *Client) QueryWhois(ctx context.Context, query string) (string, error) {
	d := net.Dialer{Timeout: c.whoisTimeout}
	conn, err := d.DialContext(ctx, "tcp", c.whoisServer)
	if err != nil {
		return "", fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	query = strings.TrimSpace(query) + "\r\n"
	if _, err := conn.Write([]byte(query)); err != nil {
		return "", fmt.Errorf("write failed: %w", err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, conn); err != nil {
		return "", fmt.Errorf("read failed: %w", err)
	}

	return buf.String(), nil
}

func ParseWhoisResponse(response string) WhoisInfo {
	info := WhoisInfo{}
	scanner := bufio.NewScanner(strings.NewReader(response))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "inetnum", "inet6num":
			info.Network = value
		case "CIDR":
			info.CIDR = strings.Split(value, ",")
		case "country":
			info.Country = value
		case "descr", "org-name":
			if info.OrgName == "" {
				info.OrgName = value
			}
		case "parent":
			info.Parent = value
		case "created":
			if t, err := parseWhoisDate(value); err == nil {
				info.Created = t
			}
		case "last-modified":
			if t, err := parseWhoisDate(value); err == nil {
				info.LastUpdated = t
			}
		}
	}

	return info
}

func parseWhoisDate(s string) (time.Time, error) {
	formats := []string{
		"2006-01-02T15:04:05Z",
		"20060102",
		"2006-01-02",
	}
	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized date format: %s", s)
}
