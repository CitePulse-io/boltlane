package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

type Device struct {
	Policy     Policy
	Identity   ed25519.PrivateKey
	ServerKey  ed25519.PublicKey
	HTTPClient *http.Client
}

const maxConnections = 8
const maxTransfer = 64 << 20
const maxHTTPResponse = 8 << 20
const maxDuration = 5 * time.Minute

func (d *Device) Run(ctx context.Context, url string) error {
	if !strings.HasPrefix(url, "wss://") {
		return errors.New("device requires a TLS tunnel")
	}
	ws, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPClient: d.HTTPClient})
	if err != nil {
		return err
	}
	conn := socketConn(ws)
	if err := authenticate(conn, false, d.Identity, d.ServerKey); err != nil {
		conn.Close()
		return err
	}
	session, err := yamux.Client(conn, muxConfig())
	if err != nil {
		conn.Close()
		return err
	}
	defer session.Close()
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go watchSession(watchCtx, session, ws, nil)
	capacity := make(chan struct{}, maxConnections)
	for {
		stream, err := session.Accept()
		if err != nil {
			return err
		}
		select {
		case capacity <- struct{}{}:
			go func() { defer func() { <-capacity }(); d.serve(ctx, stream) }()
		default:
			writeFrame(stream, Result{Error: "device_unavailable"})
			stream.Close()
		}
	}
}

func (d *Device) serve(ctx context.Context, stream net.Conn) {
	defer stream.Close()
	stream.SetDeadline(time.Now().Add(maxDuration))
	var open Open
	if err := readFrame(stream, &open); err != nil {
		return
	}
	if open.Version != 1 || !d.Policy.Allows(open.Host, open.Port) || (open.Method == http.MethodConnect && open.Port != 443) || (open.Method != http.MethodConnect && open.Port != 80) {
		writeFrame(stream, Result{Error: "destination_forbidden"})
		return
	}
	if open.Method == http.MethodConnect {
		d.connect(ctx, stream, open)
	} else {
		d.forward(ctx, stream, open)
	}
}

func (d *Device) connect(ctx context.Context, stream net.Conn, open Open) {
	conn, err := d.Policy.Dial(ctx, open.Host, open.Port)
	if err != nil {
		writeFrame(stream, Result{Error: classify(err)})
		return
	}
	defer conn.Close()
	if err := writeFrame(stream, Result{}); err != nil {
		return
	}
	stream.SetDeadline(time.Now().Add(maxDuration))
	// The client cannot send a ClientHello until it receives CONNECT 200.
	// No bytes are sent to the target until SNI is independently checked.
	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	name, hello, err := clientHelloName(stream)
	if err != nil || !strings.EqualFold(name, open.Host) {
		return
	}
	stream.SetReadDeadline(time.Now().Add(maxDuration))
	if _, err := conn.Write(hello); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		io.CopyN(conn, stream, maxTransfer)
		// The proxy client can close while the origin keeps its TLS socket
		// idle. Closing the origin unblocks the other copy and frees this
		// Device stream slot immediately.
		conn.Close()
		stream.Close()
		close(done)
	}()
	io.CopyN(stream, conn, maxTransfer)
	conn.Close()
	stream.Close()
	<-done
}

func (d *Device) forward(ctx context.Context, stream net.Conn, open Open) {
	request, err := http.ReadRequest(bufio.NewReader(stream))
	if err != nil {
		writeFrame(stream, Result{Error: "destination_forbidden"})
		return
	}
	defer request.Body.Close()
	if request.ContentLength > maxTransfer {
		writeFrame(stream, Result{Error: "destination_forbidden"})
		return
	}
	request.Body = http.MaxBytesReader(nil, request.Body, maxTransfer)
	host := request.Host
	if h, p, err := net.SplitHostPort(host); err == nil {
		if p != strconv.Itoa(open.Port) {
			writeFrame(stream, Result{Error: "destination_forbidden"})
			return
		}
		host = h
	}
	if !strings.EqualFold(host, open.Host) || request.Method != open.Method || request.URL.IsAbs() || request.Header.Get("Proxy-Authorization") != "" {
		writeFrame(stream, Result{Error: "destination_forbidden"})
		return
	}
	conn, err := d.Policy.Dial(ctx, open.Host, open.Port)
	if err != nil {
		writeFrame(stream, Result{Error: classify(err)})
		return
	}
	defer conn.Close()
	request.Close = true
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := request.Write(conn); err != nil {
		writeFrame(stream, Result{Error: "destination_connection_failed"})
		return
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		writeFrame(stream, Result{Error: "destination_connection_failed"})
		return
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxHTTPResponse+1))
	if err != nil || len(body) > maxHTTPResponse {
		writeFrame(stream, Result{Error: "destination_connection_failed"})
		return
	}
	if err := writeFrame(stream, Result{}); err != nil {
		return
	}
	stream.SetDeadline(time.Now().Add(maxDuration))
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	response.TransferEncoding = nil
	response.Header.Del("Transfer-Encoding")
	response.Header.Del("Content-Length")
	response.Write(stream)
}

func classify(err error) string {
	if errors.Is(err, ErrForbidden) {
		return "destination_forbidden"
	}
	return "destination_connection_failed"
}
