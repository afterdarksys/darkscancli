package client

import (
	"testing"
	"time"
)

func TestNewClientRequiresToken(t *testing.T) {
	if _, err := NewClient("", "", "", time.Second, time.Second); err == nil {
		t.Fatal("expected missing token to be rejected")
	}
}

func TestNewClientRejectsRemotePlainHTTP(t *testing.T) {
	if _, err := NewClient(
		"http://daemon.example.com", "", "secret", time.Second, time.Millisecond,
	); err == nil {
		t.Fatal("expected remote plaintext HTTP to be rejected")
	}
}
