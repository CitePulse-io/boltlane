package proxy

import (
	"bufio"
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

	"github.com/hashicorp/yamux"
)

func TestConnectClosesDeviceStreamWhenClientDisconnects(t *testing.T) {
	serverStream, deviceStream := net.Pipe()
	defer deviceStream.Close()
	finished := make(chan struct{})
	s := &Server{}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.connect(w, r, serverStream, time.Now())
		close(finished)
	}))
	defer proxy.Close()
	go writeFrame(deviceStream, Result{})
	client, err := net.Dial("tcp", proxy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(client, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	reader := bufio.NewReader(client)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	client.Close()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		deviceStream.Close()
		<-finished
		t.Fatal("proxy held CONNECT open after client disconnected")
	}
}

func TestDeviceReleasesConnectWhenProxyStreamCloses(t *testing.T) {
	deviceStream, proxyStream := net.Pipe()
	defer proxyStream.Close()
	deviceTarget, origin := net.Pipe()
	defer origin.Close()
	policy := Policy{Hosts: []string{"example.com"}, Ports: []int{443}}
	policy.Resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.215.14")}, nil
	}
	policy.DialIP = func(context.Context, string, int) (net.Conn, error) { return deviceTarget, nil }
	d := &Device{Policy: policy}
	finished := make(chan struct{})
	go func() {
		d.connect(context.Background(), deviceStream, Open{Host: "example.com", Port: 443, Method: http.MethodConnect})
		close(finished)
	}()
	var result Result
	if err := readFrame(proxyStream, &result); err != nil || result.Error != "" {
		t.Fatalf("connect opening result: %+v, %v", result, err)
	}
	client := tls.Client(proxyStream, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true})
	go client.Handshake()
	helloReceived := make(chan struct{})
	go func() {
		buffer := make([]byte, 4096)
		origin.Read(buffer)
		close(helloReceived)
		io.Copy(io.Discard, origin)
	}()
	select {
	case <-helloReceived:
	case <-time.After(2 * time.Second):
		t.Fatal("Device did not forward the TLS ClientHello")
	}
	proxyStream.Close()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		origin.Close()
		<-finished
		t.Fatal("Device held its CONNECT slot after the proxy stream closed")
	}
}

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

func TestLinkDetectsStaleSession(t *testing.T) {
	_, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	_, deviceKey, _ := ed25519.GenerateKey(rand.Reader)
	s := &Server{Identity: serverKey, DeviceKey: deviceKey.Public().(ed25519.PublicKey)}
	client, serverConn := net.Pipe()
	defer client.Close()
	// A yamux session over a pipe whose peer is gone: IsClosed stays false
	// after the pipe breaks, so only the liveness ping catches it.
	serverConn.Close()
	config := muxConfig()
	config.LogOutput = io.Discard
	session, err := yamux.Client(client, config)
	if err != nil {
		t.Fatal(err)
	}
	s.Link.Set(session)
	if _, err := s.Link.Open(); err == nil {
		t.Fatal("stale session accepted")
	}
	if !session.IsClosed() {
		t.Fatal("stale session was not closed after failed ping")
	}
}

func TestWatchSessionKeepaliveFailure(t *testing.T) {
	client, serverConn := net.Pipe()
	defer serverConn.Close()
	config := muxConfig()
	config.LogOutput = io.Discard
	// yamux's own keepalive (interval 20s) would close the session at ~30s;
	// shorten the interval so this test exercises the failure path quickly.
	config.KeepAliveInterval = 500 * time.Millisecond
	config.ConnectionWriteTimeout = 1 * time.Second
	session, err := yamux.Client(client, config)
	if err != nil {
		t.Fatal(err)
	}
	reasons := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		watchSession(context.Background(), session, nil, func(reason string) { reasons <- reason; close(done) })
	}()
	// With no yamux server answering pings, either the watcher's probe or
	// yamux's own keepalive must fail and close the session promptly.
	deadline := time.Now().Add(15 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	closed := false
	for !closed && time.Now().Before(deadline) {
		<-ticker.C
		closed = session.IsClosed()
	}
	if !closed {
		t.Fatal("session not closed after keepalive failure")
	}
	select {
	case reason := <-reasons:
		if reason != "keepalive_failed" && reason != "keepalive_timeout" && reason != "session_ended" {
			t.Fatalf("unexpected close reason: %s", reason)
		}
	default:
	}
}

func TestWatchSessionStopsWhenSessionCloses(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	config := muxConfig()
	config.LogOutput = io.Discard
	session, err := yamux.Client(client, config)
	if err != nil {
		t.Fatal(err)
	}
	reason := make(chan string, 1)
	go watchSession(context.Background(), session, nil, func(event string) { reason <- event })
	session.Close()
	select {
	case got := <-reason:
		if got != "session_ended" {
			t.Fatalf("close reason = %q, want session_ended", got)
		}
	case <-time.After(time.Second):
		t.Fatal("watcher did not exit when session closed")
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
	closed := make(chan struct{}, 1)
	s := &Server{Policy: policy, Username: "requestor", Password: "secret", Identity: serverKey, DeviceKey: deviceKey.Public().(ed25519.PublicKey), Logger: func(format string, _ ...any) {
		if strings.HasPrefix(format, "event=connect_done") {
			closed <- struct{}{}
		}
	}}
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
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: transport}
	response, err := client.Get("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || string(body) != "tls target" {
		t.Fatalf("got %d %q", response.StatusCode, body)
	}
	transport.CloseIdleConnections()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		s.Link.Set(nil)
		t.Fatal("CONNECT stream stayed open after client closed its idle connection")
	}
}
