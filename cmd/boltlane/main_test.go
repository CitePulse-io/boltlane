package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestServerIdentityFromSecretVariable(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BOLTLANE_SERVER_KEY_B64", base64.StdEncoding.EncodeToString(key))
	loaded, err := privateKey("BOLTLANE_SERVER_KEY_FILE")
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Equal(key) {
		t.Fatal("Server identity changed while loading")
	}
	t.Setenv("BOLTLANE_SERVER_KEY_FILE", "/unused")
	if _, err := privateKey("BOLTLANE_SERVER_KEY_FILE"); err == nil {
		t.Fatal("ambiguous key source accepted")
	}
}
