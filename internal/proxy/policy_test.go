package proxy

import (
	"context"
	"net"
	"testing"
)

func TestDestinationPolicyRejectsForbiddenAddresses(t *testing.T) {
	policy := Policy{Hosts: []string{"example.com"}, Ports: []int{443}, Resolve: func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.215.14"), net.ParseIP("169.254.169.254")}, nil
	}}
	if _, err := policy.Dial(context.Background(), "example.com", 443); err == nil {
		t.Fatal("a public answer must not hide a forbidden DNS answer")
	}
	for _, host := range []string{"127.0.0.1", "localhost", "unapproved.example"} {
		if _, err := policy.Dial(context.Background(), host, 443); err == nil {
			t.Fatalf("accepted forbidden host %q", host)
		}
	}
}
