package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestServerEventStream(t *testing.T) {
	_, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	_, deviceKey, _ := ed25519.GenerateKey(rand.Reader)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("served through device secret-content"))
	}))
	defer target.Close()
	targetAddress := strings.TrimPrefix(target.URL, "http://")
	policy := Policy{Hosts: []string{"example.com"}, Ports: []int{80, 443}}
	devicePolicy := policy
	devicePolicy.Resolve = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.215.14")}, nil }
	devicePolicy.DialIP = func(ctx context.Context, _ string, _ int) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", targetAddress)
	}
	var logs []string
	s := &Server{Policy: policy, Username: "requestor", Password: "secret", Identity: serverKey, DeviceKey: deviceKey.Public().(ed25519.PublicKey), Logger: func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}}
	proxy := httptest.NewTLSServer(s)
	defer proxy.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	device := &Device{Policy: devicePolicy, Identity: deviceKey, ServerKey: serverKey.Public().(ed25519.PublicKey), HTTPClient: proxy.Client()}
	go device.Run(ctx, "wss"+strings.TrimPrefix(proxy.URL, "https")+"/boltlane/v1/tunnel")
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := s.Link.Open()
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("device did not connect")
		}
		time.Sleep(10 * time.Millisecond)
	}
	proxyURL, _ := url.Parse(proxy.URL)
	proxyURL.User = url.UserPassword("requestor", "secret")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	response, err := client.Get("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	response, err = client.Get("http://forbidden.example/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	unauthenticated := &http.Client{Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse(proxy.URL)
	}, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	response, err = unauthenticated.Get("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	combined := strings.Join(logs, "\n")
	for _, want := range []string{"event=tunnel_connected", "event=request_open", "event=request_done", "event=destination_forbidden", "event=auth_failed"} {
		if !strings.Contains(combined, want) {
			t.Errorf("event %q missing from server log: %s", want, combined)
		}
	}
	if strings.Contains(combined, "secret-content") || strings.Contains(combined, "secret") {
		t.Errorf("response or credential content leaked into server log: %s", combined)
	}
}

func TestAuthenticatedProxyThroughDevice(t *testing.T) {
	_, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	_, deviceKey, _ := ed25519.GenerateKey(rand.Reader)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" {
			t.Errorf("unexpected target host: %s", r.Host)
		}
		if r.URL.Path == "/large" {
			w.Write(make([]byte, maxHTTPResponse+1))
			return
		}
		w.Write([]byte("served through device"))
	}))
	defer target.Close()
	targetAddress := strings.TrimPrefix(target.URL, "http://")
	policy := Policy{Hosts: []string{"example.com"}, Ports: []int{80, 443}}
	devicePolicy := policy
	devicePolicy.Resolve = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.215.14")}, nil }
	devicePolicy.DialIP = func(ctx context.Context, _ string, _ int) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", targetAddress)
	}
	s := &Server{Policy: policy, Username: "requestor", Password: "secret", Identity: serverKey, DeviceKey: deviceKey.Public().(ed25519.PublicKey)}
	proxy := httptest.NewTLSServer(s)
	defer proxy.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	device := &Device{Policy: devicePolicy, Identity: deviceKey, ServerKey: serverKey.Public().(ed25519.PublicKey), HTTPClient: proxy.Client()}
	go device.Run(ctx, "wss"+strings.TrimPrefix(proxy.URL, "https")+"/boltlane/v1/tunnel")
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := s.Link.Open()
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("device did not connect")
		}
		time.Sleep(10 * time.Millisecond)
	}
	proxyURL, _ := url.Parse(proxy.URL)
	proxyURL.User = url.UserPassword("requestor", "secret")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	response, err := client.Get("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || string(body) != "served through device" {
		t.Fatalf("got %d %q", response.StatusCode, body)
	}
	response, err = client.Get("http://example.com/large")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 502 {
		t.Fatalf("oversized response was accepted: %d", response.StatusCode)
	}
	response, err = client.Get("http://forbidden.example/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatalf("forbidden status = %d", response.StatusCode)
	}
	unauthenticated := &http.Client{Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse(proxy.URL)
	}, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	response, err = unauthenticated.Get("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 407 {
		t.Fatalf("unauthenticated status = %d", response.StatusCode)
	}
}

func TestDeviceRejectsUnpinnedServer(t *testing.T) {
	_, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	_, deviceKey, _ := ed25519.GenerateKey(rand.Reader)
	otherKey, _, _ := ed25519.GenerateKey(rand.Reader)
	s := &Server{Identity: serverKey, DeviceKey: deviceKey.Public().(ed25519.PublicKey)}
	proxy := httptest.NewTLSServer(s)
	defer proxy.Close()
	d := &Device{Identity: deviceKey, ServerKey: otherKey, HTTPClient: proxy.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := d.Run(ctx, "wss"+strings.TrimPrefix(proxy.URL, "https")+"/boltlane/v1/tunnel")
	if err == nil || !strings.Contains(err.Error(), "server identity mismatch") {
		t.Fatalf("pin mismatch: %v", err)
	}
	if _, err := s.Link.Open(); err == nil {
		t.Fatal("untrusted device became available")
	}
}

func TestHTTPSConnectThroughDevice(t *testing.T) {
	_, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	_, deviceKey, _ := ed25519.GenerateKey(rand.Reader)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("tls target")) }))
	defer target.Close()
	policy := Policy{Hosts: []string{"example.com"}, Ports: []int{443}}
	devicePolicy := policy
	devicePolicy.Resolve = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.215.14")}, nil }
	devicePolicy.DialIP = func(ctx context.Context, _ string, _ int) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(target.URL, "https://"))
	}
	s := &Server{Policy: policy, Username: "requestor", Password: "secret", Identity: serverKey, DeviceKey: deviceKey.Public().(ed25519.PublicKey)}
	proxy := httptest.NewTLSServer(s)
	defer proxy.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &Device{Policy: devicePolicy, Identity: deviceKey, ServerKey: serverKey.Public().(ed25519.PublicKey), HTTPClient: proxy.Client()}
	go d.Run(ctx, "wss"+strings.TrimPrefix(proxy.URL, "https")+"/boltlane/v1/tunnel")
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := s.Link.Open()
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("device did not connect")
		}
		time.Sleep(10 * time.Millisecond)
	}
	proxyURL, _ := url.Parse(proxy.URL)
	proxyURL.User = url.UserPassword("requestor", "secret")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	response, err := client.Get("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || string(body) != "tls target" {
		t.Fatalf("got %d %q", response.StatusCode, body)
	}
}
