package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestProbeAcceptsOnlyApprovedHosts(t *testing.T) {
	cases := map[string]bool{
		"https://quikrstuff.com/":         true,
		"https://api.ipify.org/":          true,
		"https://evil.example.com/":       false,
		"http://api.ipify.org/":           false,
		"https://api.ipify.org:443/":      false,
		"https://api.ipify.org.evil.com/": false,
	}
	for rawURL, want := range cases {
		_, _, err := probeValidation(rawURL)
		if (err == nil) != want {
			t.Errorf("probeValidation(%q) error %v, want valid=%v", rawURL, err, want)
		}
	}
}

func TestCheckChallengeCFMitigated(t *testing.T) {
	response := &http.Response{StatusCode: 200, Header: http.Header{}}
	response.Header.Set("CF-Mitigated", "challenge")
	if err := checkChallenge(response, []byte("<html>hello</html>")); err == nil {
		t.Fatal("CF-Mitigated challenge header not detected")
	}
	clean := &http.Response{StatusCode: 200, Header: http.Header{}}
	if err := checkChallenge(clean, []byte("<html>quikrstuff books</html>")); err != nil {
		t.Fatalf("false positive on clean page: %v", err)
	}
	if err := checkChallenge(clean, []byte("we never use captcha widgets here")); err != nil {
		t.Fatalf("innocuous 'captcha' text flagged: %v", err)
	}
}

func TestDescriptorURLs(t *testing.T) {
	for _, rawURL := range []string{"https://quikrstuff.com/llms.txt", "https://quikrstuff.com/.well-known/llms.txt", "https://quikrstuff.com/sitemap.xml"} {
		if !descriptorURLs[rawURL] {
			t.Errorf("%q missing from descriptor set", rawURL)
		}
	}
	if descriptorURLs["https://quikrstuff.com/"] {
		t.Error("homepage wrongly classified as descriptor")
	}
	if !strings.Contains(declaredUA, "CitePulseBot") {
		t.Error("declared UA missing")
	}
}
