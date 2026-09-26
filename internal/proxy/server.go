package proxy

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

type Server struct {
	Policy             Policy
	Username, Password string
	Identity           ed25519.PrivateKey
	DeviceKey          ed25519.PublicKey
	Link               Link
	// Logger receives operational events (tunnel lifecycle, per-request
	// outcomes, auth and policy refusals). Metadata only: never request or
	// response content, credentials, or keys.
	Logger func(format string, args ...any)
	// ErrorLogger receives failures that need attention; routine events use Logger.
	ErrorLogger func(format string, args ...any)
}

func (s *Server) logf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger(format, args...)
	}
}

func (s *Server) errorf(format string, args ...any) {
	if s.ErrorLogger != nil {
		s.ErrorLogger(format, args...)
	} else {
		s.logf(format, args...)
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/boltlane/v1/tunnel" && r.Method == http.MethodGet {
		s.tunnel(w, r)
		return
	}
	var username, password string
	var ok bool
	if value := r.Header.Get("Proxy-Authorization"); value != "" {
		probe := &http.Request{Header: http.Header{"Authorization": []string{value}}}
		username, password, ok = probe.BasicAuth()
	}
	if !ok || subtle.ConstantTimeCompare([]byte(username), []byte(s.Username)) != 1 || !sameSecret(password, s.Password) {
		s.errorf("event=auth_failed remote=%s", r.RemoteAddr)
		w.Header().Set("Proxy-Authenticate", `Basic realm="boltlane"`)
		proxyError(w, http.StatusProxyAuthRequired, "authentication_failed")
		return
	}
	host, port, err := destination(r)
	if err != nil || !s.Policy.Allows(host, port) {
		s.logf("event=destination_forbidden host=%s port=%d method=%s remote=%s", host, port, r.Method, r.RemoteAddr)
		proxyError(w, http.StatusForbidden, "destination_forbidden")
		return
	}
	stream, err := s.Link.Open()
	if err != nil {
		s.errorf("event=device_unavailable host=%s port=%d method=%s", host, port, r.Method)
		proxyError(w, http.StatusServiceUnavailable, "device_unavailable")
		return
	}
	defer stream.Close()
	start := time.Now()
	s.logf("event=request_open method=%s host=%s port=%d", r.Method, host, port)
	stream.SetDeadline(time.Now().Add(15 * time.Second))
	if err = writeFrame(stream, Open{Version: 1, Method: r.Method, Host: host, Port: port}); err != nil {
		s.errorf("event=tunnel_interrupted host=%s port=%d method=%s", host, port, r.Method)
		proxyError(w, http.StatusServiceUnavailable, "tunnel_interrupted")
		return
	}
	if r.Method == http.MethodConnect {
		s.connect(w, r, stream, start)
	} else {
		s.forward(w, r, stream, start)
	}
}

func sameSecret(a, b string) bool {
	x, y := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(x[:], y[:]) == 1
}

func destination(r *http.Request) (string, int, error) {
	if r.Method != http.MethodConnect && (r.URL.Scheme != "http" || r.URL.Host == "") {
		return "", 0, ErrForbidden
	}
	address := r.URL.Host
	defaultPort := "80"
	if r.Method == http.MethodConnect {
		if r.URL.Host != r.Host {
			return "", 0, ErrForbidden
		}
		address, defaultPort = r.Host, "443"
	}
	if r.Method != http.MethodConnect && !strings.EqualFold(r.Host, r.URL.Host) {
		return "", 0, ErrForbidden
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host, port = address, defaultPort
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strings.ContainsAny(host, " /@") {
		return "", 0, ErrForbidden
	}
	return strings.ToLower(host), n, nil
}

func (s *Server) forward(w http.ResponseWriter, r *http.Request, stream net.Conn, start time.Time) {
	request := r.Clone(r.Context())
	request.Header.Del("Proxy-Authorization")
	request.Header.Del("Proxy-Connection")
	request.Close = true
	if err := request.Write(stream); err != nil {
		s.errorf("event=tunnel_interrupted method=%s host=%s", request.Method, request.URL.Host)
		proxyError(w, http.StatusServiceUnavailable, "tunnel_interrupted")
		return
	}
	var result Result
	if err := readFrame(stream, &result); err != nil {
		s.errorf("event=tunnel_interrupted method=%s host=%s", request.Method, request.URL.Host)
		proxyError(w, http.StatusServiceUnavailable, "tunnel_interrupted")
		return
	}
	if result.Error != "" {
		if result.Error == "destination_forbidden" {
			s.logf("event=device_refused method=%s host=%s reason=%s", request.Method, request.URL.Host, result.Error)
		} else {
			s.errorf("event=device_refused method=%s host=%s reason=%s", request.Method, request.URL.Host, result.Error)
		}
		writeResultError(w, result.Error)
		return
	}
	stream.SetDeadline(time.Time{})
	response, err := http.ReadResponse(bufio.NewReader(stream), request)
	if err != nil {
		s.errorf("event=destination_connection_failed method=%s host=%s", request.Method, request.URL.Host)
		proxyError(w, http.StatusBadGateway, "destination_connection_failed")
		return
	}
	defer response.Body.Close()
	s.logf("event=request_done method=%s host=%s status=%d duration_ms=%d", request.Method, request.URL.Host, response.StatusCode, time.Since(start).Milliseconds())
	for key, values := range response.Header {
		if strings.EqualFold(key, "Proxy-Authorization") || strings.EqualFold(key, "Connection") {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	io.Copy(w, response.Body)
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request, stream net.Conn, start time.Time) {
	host := r.Host
	var result Result
	if err := readFrame(stream, &result); err != nil {
		s.errorf("event=tunnel_interrupted method=CONNECT host=%s", host)
		proxyError(w, http.StatusServiceUnavailable, "tunnel_interrupted")
		return
	}
	if result.Error != "" {
		if result.Error == "destination_forbidden" {
			s.logf("event=device_refused method=CONNECT host=%s reason=%s", host, result.Error)
		} else {
			s.errorf("event=device_refused method=CONNECT host=%s reason=%s", host, result.Error)
		}
		writeResultError(w, result.Error)
		return
	}
	stream.SetDeadline(time.Time{})
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		proxyError(w, http.StatusInternalServerError, "hijack_unavailable")
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	s.logf("event=connect_established host=%s", host)
	// Buffered bytes after the CONNECT headers are still part of the TLS hello.
	done := make(chan struct{})
	var upstream, downstream int64
	count := func(dst io.Writer, src io.Reader) int64 {
		n, _ := io.Copy(dst, src)
		return n
	}
	go func() {
		// Hide bufio.Reader's WriteTo optimization: when its buffer is
		// empty, it can issue a zero-length write to a yamux stream and
		// stall instead of waiting for bytes from the client.
		upstream = count(stream, struct{ io.Reader }{buffered})
		// A client can finish while the origin leaves its TLS connection
		// open. Tear down the tunnel now so the Device frees its slot.
		stream.Close()
		client.Close()
		close(done)
	}()
	downstream = count(client, stream)
	client.Close()
	stream.Close()
	<-done
	s.logf("event=connect_done host=%s duration_ms=%d upstream_bytes=%d downstream_bytes=%d", host, time.Since(start).Milliseconds(), upstream, downstream)
}

func (s *Server) tunnel(w http.ResponseWriter, r *http.Request) {
	s.logf("event=tunnel_attempt remote=%s", r.RemoteAddr)
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
	if err != nil {
		return
	}
	conn := socketConn(ws)
	if err := authenticate(conn, true, s.Identity, s.DeviceKey); err != nil {
		s.errorf("event=tunnel_auth_failed remote=%s", r.RemoteAddr)
		conn.Close()
		return
	}
	s.logf("event=tunnel_connected remote=%s", r.RemoteAddr)
	session, err := yamux.Server(conn, muxConfig())
	if err != nil {
		s.errorf("event=tunnel_error stage=yamux")
		conn.Close()
		return
	}
	s.Link.Set(session)
	watchSession(r.Context(), session, ws, func(reason string) {
		s.logf("event=tunnel_closed reason=%s next=device_reconnect", reason)
	})
}

func proxyError(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Proxy-Status", fmt.Sprintf(`boltlane; error="%s"`, reason))
	http.Error(w, http.StatusText(status), status)
}

func writeResultError(w http.ResponseWriter, reason string) {
	switch reason {
	case "destination_forbidden":
		proxyError(w, http.StatusForbidden, reason)
	case "destination_connection_failed":
		proxyError(w, http.StatusBadGateway, reason)
	default:
		proxyError(w, http.StatusServiceUnavailable, "tunnel_interrupted")
	}
}
