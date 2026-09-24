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
		w.Header().Set("Proxy-Authenticate", `Basic realm="boltlane"`)
		proxyError(w, http.StatusProxyAuthRequired, "authentication_failed")
		return
	}
	host, port, err := destination(r)
	if err != nil || !s.Policy.Allows(host, port) {
		proxyError(w, http.StatusForbidden, "destination_forbidden")
		return
	}
	stream, err := s.Link.Open()
	if err != nil {
		proxyError(w, http.StatusServiceUnavailable, "device_unavailable")
		return
	}
	defer stream.Close()
	stream.SetDeadline(time.Now().Add(15 * time.Second))
	if err = writeFrame(stream, Open{Version: 1, Method: r.Method, Host: host, Port: port}); err != nil {
		proxyError(w, http.StatusServiceUnavailable, "tunnel_interrupted")
		return
	}
	if r.Method == http.MethodConnect {
		s.connect(w, r, stream)
	} else {
		s.forward(w, r, stream)
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

func (s *Server) forward(w http.ResponseWriter, r *http.Request, stream net.Conn) {
	request := r.Clone(r.Context())
	request.Header.Del("Proxy-Authorization")
	request.Header.Del("Proxy-Connection")
	request.Close = true
	if err := request.Write(stream); err != nil {
		proxyError(w, http.StatusServiceUnavailable, "tunnel_interrupted")
		return
	}
	var result Result
	if err := readFrame(stream, &result); err != nil {
		proxyError(w, http.StatusServiceUnavailable, "tunnel_interrupted")
		return
	}
	if result.Error != "" {
		writeResultError(w, result.Error)
		return
	}
	stream.SetDeadline(time.Time{})
	response, err := http.ReadResponse(bufio.NewReader(stream), request)
	if err != nil {
		proxyError(w, http.StatusBadGateway, "destination_connection_failed")
		return
	}
	defer response.Body.Close()
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

func (s *Server) connect(w http.ResponseWriter, r *http.Request, stream net.Conn) {
	var result Result
	if err := readFrame(stream, &result); err != nil {
		proxyError(w, http.StatusServiceUnavailable, "tunnel_interrupted")
		return
	}
	if result.Error != "" {
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
	// Buffered bytes after the CONNECT headers are still part of the TLS hello.
	done := make(chan struct{})
	go func() { io.Copy(stream, buffered); close(done) }()
	io.Copy(client, stream)
	client.Close()
	stream.Close()
	<-done
}

func (s *Server) tunnel(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
	if err != nil {
		return
	}
	conn := socketConn(ws)
	if err := authenticate(conn, true, s.Identity, s.DeviceKey); err != nil {
		conn.Close()
		return
	}
	session, err := yamux.Server(conn, nil)
	if err != nil {
		conn.Close()
		return
	}
	s.Link.Set(session)
	<-session.CloseChan()
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
