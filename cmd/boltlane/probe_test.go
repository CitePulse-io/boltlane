package main

import "testing"

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
