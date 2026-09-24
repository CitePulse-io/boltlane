package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/CitePulse-io/boltlane/internal/proxy"
)

func main() {
	log.SetFlags(log.LstdFlags)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: boltlane keygen <private-key-file> | server | device | probe <https-url>")
	}
	switch os.Args[1] {
	case "keygen":
		if len(os.Args) != 3 {
			return errors.New("usage: boltlane keygen <private-key-file>")
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		file, err := os.OpenFile(os.Args[2], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		if _, err := file.WriteString(base64.StdEncoding.EncodeToString(private)); err != nil {
			file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		fmt.Println("public key:", base64.StdEncoding.EncodeToString(public))
		fmt.Println("fingerprint:", fingerprint(public))
		return nil
	case "server":
		return server()
	case "device":
		return device()
	case "probe":
		if len(os.Args) != 3 {
			return errors.New("usage: boltlane probe <https-url>")
		}
		return probe(os.Args[2])
	default:
		return errors.New("unknown command")
	}
}

func publicKey(name string) (ed25519.PublicKey, error) {
	value, err := base64.StdEncoding.DecodeString(os.Getenv(name))
	if err != nil || len(value) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid %s", name)
	}
	return ed25519.PublicKey(value), nil
}

func privateKey(name string) (ed25519.PrivateKey, error) {
	if name == "BOLTLANE_SERVER_KEY_FILE" && os.Getenv("BOLTLANE_SERVER_KEY_B64") != "" {
		if os.Getenv(name) != "" {
			return nil, errors.New("configure only one Server identity key source")
		}
		value, err := base64.StdEncoding.DecodeString(os.Getenv("BOLTLANE_SERVER_KEY_B64"))
		if err != nil || len(value) != ed25519.PrivateKeySize {
			return nil, errors.New("invalid Server identity key")
		}
		return ed25519.PrivateKey(value), nil
	}
	path := os.Getenv(name)
	if path == "" {
		return nil, fmt.Errorf("missing %s", name)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("identity key file must be mode 0600")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	value, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(value) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid identity key")
	}
	return ed25519.PrivateKey(value), nil
}

func fingerprint(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

func policy() (proxy.Policy, error) {
	path := os.Getenv("BOLTLANE_POLICY_FILE")
	if path == "" {
		return proxy.Policy{}, errors.New("missing BOLTLANE_POLICY_FILE")
	}
	f, err := os.Open(path)
	if err != nil {
		return proxy.Policy{}, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var p proxy.Policy
	if err := dec.Decode(&p); err != nil {
		return p, err
	}
	if len(p.Hosts) == 0 || len(p.Ports) == 0 {
		return p, errors.New("empty policy")
	}
	for _, host := range p.Hosts {
		if host == "" || host != strings.ToLower(host) || strings.ContainsAny(host, " /:@") || net.ParseIP(host) != nil {
			return p, errors.New("invalid policy hostname")
		}
	}
	for _, port := range p.Ports {
		if port != 80 && port != 443 {
			return p, errors.New("only HTTP/HTTPS ports supported")
		}
	}
	return p, nil
}

func server() error {
	identity, err := privateKey("BOLTLANE_SERVER_KEY_FILE")
	if err != nil {
		return err
	}
	deviceKey, err := publicKey("BOLTLANE_DEVICE_PUBLIC_KEY")
	if err != nil {
		return err
	}
	p, err := policy()
	if err != nil {
		return err
	}
	user, password := os.Getenv("BOLTLANE_PROXY_USER"), os.Getenv("BOLTLANE_PROXY_PASSWORD")
	if user == "" || len(password) < 24 {
		return errors.New("proxy credentials missing or weak")
	}
	s := &proxy.Server{Policy: p, Username: user, Password: password, Identity: identity, DeviceKey: deviceKey, Logger: func(format string, args ...any) {
		log.Printf(format, args...)
	}}
	addr := os.Getenv("BOLTLANE_LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second}
	cert, key := os.Getenv("BOLTLANE_TLS_CERT"), os.Getenv("BOLTLANE_TLS_KEY")
	if cert == "" || key == "" {
		if os.Getenv("BOLTLANE_UNSAFE_TRUSTED_PRIVATE_LISTENER") != "yes" {
			return errors.New("TLS required (or explicitly acknowledge trusted private listener)")
		}
		log.Print("server listening behind trusted private TLS termination")
		return server.Serve(listener)
	}
	log.Print("server listening with TLS")
	return server.ServeTLS(listener, cert, key)
}

func device() error {
	flags := flag.NewFlagSet("device", flag.ContinueOnError)
	approved := flags.String("approve-fingerprint", "", "confirmed Server identity SHA-256 fingerprint")
	approvePolicy := flags.Bool("approve-policy", false, "confirm the local hostname/port policy")
	if err := flags.Parse(os.Args[2:]); err != nil {
		return err
	}
	identity, err := privateKey("BOLTLANE_DEVICE_KEY_FILE")
	if err != nil {
		return err
	}
	serverKey, err := publicKey("BOLTLANE_SERVER_PUBLIC_KEY")
	if err != nil {
		return err
	}
	if *approved != fingerprint(serverKey) {
		return errors.New("Server identity not approved or fingerprint mismatch")
	}
	p, err := policy()
	if err != nil {
		return err
	}
	if !*approvePolicy {
		return errors.New("Device policy requires explicit approval")
	}
	endpoint := os.Getenv("BOLTLANE_TUNNEL_URL")
	if !strings.HasPrefix(endpoint, "wss://") {
		return errors.New("tunnel URL must use wss")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/boltlane/v1/tunnel" {
		return errors.New("invalid tunnel URL")
	}
	log.Printf("approved Device policy: hosts=%v ports=%v server fingerprint=%s", p.Hosts, p.Ports, *approved)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	d := &proxy.Device{Policy: p, Identity: identity, ServerKey: serverKey}
	for ctx.Err() == nil {
		if err := d.Run(ctx, endpoint); err != nil && ctx.Err() == nil {
			if errors.Is(err, proxy.ErrServerIdentityMismatch) {
				return err
			}
			log.Printf("tunnel disconnected: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
		}
	}
	return nil
}
