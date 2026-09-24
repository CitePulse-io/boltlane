package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

var ErrForbidden = errors.New("destination forbidden")

// Policy is independently configured at each enforcement boundary. DNS is
// always resolved at the Device; the Server only performs a hostname check.
type Policy struct {
	Hosts   []string
	Ports   []int
	Resolve func(context.Context, string) ([]net.IP, error)
	DialIP  func(context.Context, string, int) (net.Conn, error)
}

func (p Policy) Allows(host string, port int) bool {
	normalized := strings.ToLower(strings.TrimSuffix(host, "."))
	return normalized != "" && normalized != "localhost" && !strings.HasSuffix(normalized, ".localhost") && normalized != "metadata.google.internal" && net.ParseIP(host) == nil && slices.Contains(p.Ports, port) && slices.Contains(p.Hosts, normalized)
}

func (p Policy) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	if !p.Allows(host, port) {
		return nil, ErrForbidden
	}
	resolve := p.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	ips, err := resolve(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("unverifiable destination: %w", errOrEmpty(err))
	}
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok || !publicAddress(addr.Unmap()) {
			return nil, ErrForbidden
		}
	}
	dialer := net.Dialer{Timeout: connectTimeout}
	for _, ip := range ips {
		dial := p.DialIP
		if dial == nil {
			dial = func(ctx context.Context, ip string, port int) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
			}
		}
		conn, dialErr := dial(ctx, ip.String(), port)
		if dialErr == nil {
			return conn, nil
		}
		err = dialErr
	}
	return nil, fmt.Errorf("destination connection: %w", err)
}

func errOrEmpty(err error) error {
	if err == nil {
		return errors.New("empty DNS answer")
	}
	return err
}

func publicAddress(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	// Block reserved and shared ranges as well as the normal RFC1918 floor.
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/128", "2001:db8::/32", "fc00::/7", "fe80::/10"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return true
}

const connectTimeout = 10 * time.Second
