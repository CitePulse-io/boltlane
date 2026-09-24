package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var pageTitle = regexp.MustCompile(`(?is)<title[^>]*>([^<]{1,200})</title>`)

// probe is a diagnostic standard-proxy client, run inside Railway. It never
// prints credentials or response bodies and refuses off-domain redirects.
// api.ipify.org is the approved trusted exit-IP observer; it returns the
// public IP it was reached from as plain text.
func probeValidation(rawURL string) (string, *url.URL, error) {
	target, err := url.Parse(rawURL)
	if err != nil || target.Scheme != "https" || target.Port() != "" {
		return "", nil, errors.New("probe accepts only HTTPS URLs without explicit ports")
	}
	host := target.Hostname()
	if host != "quikrstuff.com" && host != "api.ipify.org" {
		return "", nil, errors.New("probe accepts only quikrstuff.com and the trusted observer api.ipify.org")
	}
	return host, target, nil
}

func probe(rawURL string) error {
	host, target, err := probeValidation(rawURL)
	if err != nil {
		return err
	}
	username, password := strings.TrimSpace(os.Getenv("BOLTLANE_PROXY_USER")), os.Getenv("BOLTLANE_PROXY_PASSWORD")
	if username == "" || password == "" {
		return errors.New("proxy credentials unavailable")
	}
	proxyURL := &url.URL{Scheme: "http", Host: "127.0.0.1:8080", User: url.UserPassword(username, password)}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 35 * time.Second, CheckRedirect: func(r *http.Request, previous []*http.Request) error {
		if len(previous) >= 3 || r.URL.Scheme != "https" || r.URL.Hostname() != target.Hostname() {
			return errors.New("redirect outside approved target")
		}
		return nil
	}}
	response, err := client.Get(target.String())
	if err != nil {
		return fmt.Errorf("proxy request failed: %w", err)
	}
	defer response.Body.Close()
	if response.Header.Get("Proxy-Status") != "" {
		return fmt.Errorf("proxy failure: HTTP %d %s", response.StatusCode, response.Header.Get("Proxy-Status"))
	}
	if response.StatusCode == 403 || response.StatusCode == 429 || response.StatusCode == 503 {
		return fmt.Errorf("target blocked or throttled: HTTP %d", response.StatusCode)
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("not usable: HTTP %d", response.StatusCode)
	}
	if host == "api.ipify.org" {
		body, err := io.ReadAll(io.LimitReader(response.Body, 128))
		if err != nil || len(body) == 0 {
			return errors.New("observer response body unavailable")
		}
		observed := strings.TrimSpace(string(body))
		if net.ParseIP(observed) == nil {
			return errors.New("observer did not return an IP address")
		}
		fmt.Printf("exit IP observed: ip=%s\n", observed)
		return nil
	}
	if !strings.HasPrefix(response.Header.Get("Content-Type"), "text/html") {
		return fmt.Errorf("not usable HTML: HTTP %d content-type %s", response.StatusCode, response.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
	if err != nil || len(body) > 8<<20 {
		return errors.New("HTML body unavailable or oversized")
	}
	match := pageTitle.FindSubmatch(body)
	if len(match) != 2 {
		return errors.New("HTML page identity missing")
	}
	title := strings.Join(strings.Fields(string(match[1])), " ")
	fmt.Printf("HTML observed: status=%d final_url=%s content_type=%s bytes=%d title=%q\n", response.StatusCode, response.Request.URL.Redacted(), response.Header.Get("Content-Type"), len(body), title)
	text := strings.ToLower(string(body))
	for _, marker := range []string{"cf-chl", "cf-turnstile", "verify you are human", "attention required", "just a moment..."} {
		if strings.Contains(text, marker) {
			return fmt.Errorf("challenge indicator %q detected; stop live probing", marker)
		}
	}
	fmt.Println("usable HTML: no known challenge indicator")
	return nil
}
