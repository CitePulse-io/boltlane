package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

const MaxFrame = 4096

// tunnelKeepalive is the interval at which the Device verifies the tunnel is
// still alive. Residential NAT and firewall state silently drops idle
// connections; without an application-level probe neither endpoint notices
// until a request fails through a dead session.
const tunnelKeepalive = 20 * time.Second

var ErrServerIdentityMismatch = errors.New("server identity mismatch")

// muxConfig returns yamux configuration with aggressive keepalives so a
// half-open connection is detected within seconds instead of minutes.
func muxConfig() *yamux.Config {
	config := yamux.DefaultConfig()
	config.EnableKeepAlive = true
	config.KeepAliveInterval = tunnelKeepalive
	config.ConnectionWriteTimeout = 10 * time.Second
	return config
}

// watchSession closes the session when the context ends or a liveness probe
// fails, and returns when yamux closes it independently.
func watchSession(ctx context.Context, session *yamux.Session, ws *websocket.Conn, onEvent func(string)) {
	ticker := time.NewTicker(tunnelKeepalive)
	defer ticker.Stop()
	reason := "session_ended"
	for {
		select {
		case <-ctx.Done():
			reason = "context_canceled"
		case <-session.CloseChan():
		case <-ticker.C:
			result := make(chan error, 1)
			go func() { _, err := session.Ping(); result <- err }()
			select {
			case err := <-result:
				if err != nil {
					reason = "keepalive_failed"
				}
			case <-time.After(10 * time.Second):
				reason = "keepalive_timeout"
			case <-ctx.Done():
				reason = "context_canceled"
			case <-session.CloseChan():
			}
			if reason == "session_ended" && ws != nil {
				pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				err := ws.Ping(pingCtx)
				cancel()
				if err != nil {
					reason = "websocket_ping_failed"
				}
			}
			if reason == "session_ended" && !session.IsClosed() {
				continue
			}
		}
		break
	}
	session.Close()
	if onEvent != nil {
		onEvent(reason)
	}
}

type Open struct {
	Version int    `json:"version"`
	Method  string `json:"method"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
}

type Result struct {
	Error string `json:"error,omitempty"`
}

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil || len(b) > MaxFrame {
		return errors.New("invalid tunnel frame")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(b)))
	if _, err = w.Write(size[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readFrame(r io.Reader, v any) error {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > MaxFrame {
		return errors.New("invalid tunnel frame size")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Authenticate binds the TLS-protected WebSocket to both long-lived identities.
// Fresh random challenges prevent reuse of an intercepted handshake.
func authenticate(conn net.Conn, server bool, own ed25519.PrivateKey, peer ed25519.PublicKey) error {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	if server {
		if err := writeFrame(conn, base64.StdEncoding.EncodeToString(challenge)); err != nil {
			return err
		}
		var answer string
		if err := readFrame(conn, &answer); err != nil {
			return err
		}
		proof, err := base64.StdEncoding.DecodeString(answer)
		if err != nil || !ed25519.Verify(peer, append([]byte("boltlane-device-v1"), challenge...), proof) {
			return errors.New("device identity mismatch")
		}
		var clientChallenge string
		if err := readFrame(conn, &clientChallenge); err != nil {
			return err
		}
		decoded, err := base64.StdEncoding.DecodeString(clientChallenge)
		if err != nil || len(decoded) != 32 {
			return errors.New("invalid challenge")
		}
		return writeFrame(conn, base64.StdEncoding.EncodeToString(ed25519.Sign(own, append([]byte("boltlane-server-v1"), decoded...))))
	}
	var serverChallenge string
	if err := readFrame(conn, &serverChallenge); err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(serverChallenge)
	if err != nil || len(decoded) != 32 {
		return errors.New("invalid challenge")
	}
	if err := writeFrame(conn, base64.StdEncoding.EncodeToString(ed25519.Sign(own, append([]byte("boltlane-device-v1"), decoded...)))); err != nil {
		return err
	}
	if err := writeFrame(conn, base64.StdEncoding.EncodeToString(challenge)); err != nil {
		return err
	}
	var answer string
	if err := readFrame(conn, &answer); err != nil {
		return err
	}
	proof, err := base64.StdEncoding.DecodeString(answer)
	if err != nil || !ed25519.Verify(peer, append([]byte("boltlane-server-v1"), challenge...), proof) {
		return ErrServerIdentityMismatch
	}
	return nil
}

func socketConn(ws *websocket.Conn) net.Conn {
	return websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
}

type Link struct {
	mu      sync.RWMutex
	session *yamux.Session
}

func (l *Link) Set(session *yamux.Session) {
	l.mu.Lock()
	old := l.session
	l.session = session
	l.mu.Unlock()
	if old != nil {
		old.Close()
	}
}

func (l *Link) Open() (net.Conn, error) {
	l.mu.RLock()
	s := l.session
	l.mu.RUnlock()
	if s == nil || s.IsClosed() {
		return nil, errors.New("no device")
	}
	if _, err := s.Ping(); err != nil {
		s.Close()
		return nil, fmt.Errorf("device unresponsive: %w", err)
	}
	stream, err := s.Open()
	if err != nil {
		return nil, fmt.Errorf("device unavailable: %w", err)
	}
	return stream, nil
}
