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

var ErrServerIdentityMismatch = errors.New("server identity mismatch")

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
	stream, err := s.Open()
	if err != nil {
		return nil, fmt.Errorf("device unavailable: %w", err)
	}
	return stream, nil
}
