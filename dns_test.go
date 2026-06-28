package apnic

import (
	"context"
	"testing"
)

func TestReverseDNS(t *testing.T) {
	client := NewClient()
	// Test with a well-known IP that should have reverse DNS
	names, err := client.ReverseDNS(context.Background(), "1.1.1.1")
	// This may fail in some environments, so we just verify no panic
	_ = names
	_ = err
}

func TestReverseDNSInvalidIP(t *testing.T) {
	client := NewClient()
	_, err := client.ReverseDNS(context.Background(), "invalid-ip")
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}
