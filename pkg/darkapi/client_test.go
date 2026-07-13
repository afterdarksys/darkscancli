package darkapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/afterdarksys/darkscan/pkg/config"
)

const testKey = "sk_test_super_secret_key_value"

func newTestClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	c, err := NewClient(config.DarkAPIConfig{Enabled: true, APIKey: testKey, BaseURL: baseURL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestNewClientRejectsEmptyKey(t *testing.T) {
	if _, err := NewClient(config.DarkAPIConfig{Enabled: true, APIKey: ""}); err == nil {
		t.Fatal("expected error for empty api key")
	}
}

func TestNewClientDefaultsBaseURL(t *testing.T) {
	c, err := NewClient(config.DarkAPIConfig{APIKey: testKey})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.baseURL != defaultBaseURL {
		t.Fatalf("baseURL = %q, want %q", c.baseURL, defaultBaseURL)
	}
}

func TestNewClientRejectsNonHTTPSRemote(t *testing.T) {
	if _, err := NewClient(config.DarkAPIConfig{APIKey: testKey, BaseURL: "http://api.darkapi.io"}); err == nil {
		t.Fatal("expected error for non-https remote base url")
	}
	// http on loopback is allowed (used by tests).
	if _, err := NewClient(config.DarkAPIConfig{APIKey: testKey, BaseURL: "http://127.0.0.1:8080"}); err != nil {
		t.Fatalf("loopback http should be allowed: %v", err)
	}
}

func TestSendsAuthAndUserAgent(t *testing.T) {
	var gotKey, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-API-Key")
		gotUA = r.Header.Get("User-Agent")
		w.Write([]byte(`{"hash":"abc","malicious":false}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	if _, err := c.LookupHash(context.Background(), "abc"); err != nil {
		t.Fatalf("LookupHash: %v", err)
	}
	if gotKey != testKey {
		t.Fatalf("X-API-Key = %q, want %q", gotKey, testKey)
	}
	if gotUA != "darkscan/"+Version {
		t.Fatalf("User-Agent = %q, want darkscan/%s", gotUA, Version)
	}
}

func TestLookupHashHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/hash/deadbeef" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(`{"hash":"deadbeef","malicious":true}`))
	}))
	defer srv.Close()

	raw, err := newTestClient(t, srv.URL).LookupHash(context.Background(), "deadbeef")
	if err != nil {
		t.Fatalf("LookupHash: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out["malicious"] != true {
		t.Fatalf("malicious = %v, want true", out["malicious"])
	}
}

func TestLookupDomainAndIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true,"path":"` + r.URL.Path + `"}`))
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	if _, err := c.LookupDomain(context.Background(), "evil.example"); err != nil {
		t.Fatalf("LookupDomain: %v", err)
	}
	if _, err := c.LookupIP(context.Background(), "203.0.113.7"); err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
}

func TestListFeedsObjectShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"feeds":[{"name":"bad-domains","count":42},{"name":"bad-ips","count":7}]}`))
	}))
	defer srv.Close()

	fl, err := newTestClient(t, srv.URL).ListFeeds(context.Background())
	if err != nil {
		t.Fatalf("ListFeeds: %v", err)
	}
	if len(fl.Feeds) != 2 || fl.Feeds[0].Name != "bad-domains" || fl.Feeds[0].Count != 42 {
		t.Fatalf("feeds = %+v", fl.Feeds)
	}
}

func TestListFeedsArrayShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"name":"bad-domains"},{"name":"bad-ips"}]`))
	}))
	defer srv.Close()

	fl, err := newTestClient(t, srv.URL).ListFeeds(context.Background())
	if err != nil {
		t.Fatalf("ListFeeds: %v", err)
	}
	if len(fl.Feeds) != 2 {
		t.Fatalf("feeds len = %d, want 2", len(fl.Feeds))
	}
}

func TestReputationLookup(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		w.Write([]byte(`{"indicator":"1.2.3.4","score":90}`))
	}))
	defer srv.Close()

	if _, err := newTestClient(t, srv.URL).ReputationLookup(context.Background(), "1.2.3.4", "ip"); err != nil {
		t.Fatalf("ReputationLookup: %v", err)
	}
	if body["indicator"] != "1.2.3.4" || body["type"] != "ip" {
		t.Fatalf("request body = %+v", body)
	}
}

func TestReputationLookupBulkLimit(t *testing.T) {
	c := newTestClient(t, "https://api.darkapi.io")
	many := make([]string, maxBulkItems+1)
	if _, err := c.ReputationLookupBulk(context.Background(), many); err == nil {
		t.Fatal("expected error for oversized bulk request")
	}
}

func TestPackageCheckTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ecosystem":"npm","name":"lodahs","malicious":true,"typosquat":true,"risk":"critical"}`))
	}))
	defer srv.Close()

	res, err := newTestClient(t, srv.URL).PackageCheck(context.Background(), PackageRef{Ecosystem: "npm", Name: "lodahs"})
	if err != nil {
		t.Fatalf("PackageCheck: %v", err)
	}
	if !res.Malicious || !res.Typosquat || res.Risk != "critical" {
		t.Fatalf("result = %+v", res)
	}
	if len(res.Raw) == 0 {
		t.Fatal("expected Raw to be populated")
	}
}

func TestIdentityExposure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"value":"user@example.com","breaches":3}`))
	}))
	defer srv.Close()

	if _, err := newTestClient(t, srv.URL).IdentityExposure(context.Background(), "user@example.com"); err != nil {
		t.Fatalf("IdentityExposure: %v", err)
	}
}

func TestUnauthorizedMapsToSentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid api key"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(t, srv.URL).LookupHash(context.Background(), "x")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("errors.Is ErrUnauthorized = false, err = %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected *APIError with 401, got %v", err)
	}
}

func TestRateLimitedCarriesRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "42")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":"rate limited"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(t, srv.URL).LookupIP(context.Background(), "1.1.1.1")
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("errors.Is ErrRateLimited = false, err = %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.RetryAfter != 42 {
		t.Fatalf("expected RetryAfter=42, got %v", err)
	}
}

func TestOversizedResponseRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		big := strings.Repeat("A", maxResponseBytes+1024)
		w.Write([]byte(big))
	}))
	defer srv.Close()

	if _, err := newTestClient(t, srv.URL).LookupHash(context.Background(), "x"); err == nil {
		t.Fatal("expected error for oversized response body")
	}
}

func TestMalformedJSONRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not valid json`))
	}))
	defer srv.Close()

	// PackageCheck decodes into a typed struct, so malformed JSON must fail closed.
	if _, err := newTestClient(t, srv.URL).PackageCheck(context.Background(), PackageRef{Ecosystem: "npm", Name: "x"}); err == nil {
		t.Fatal("expected error for malformed JSON response")
	}
}

func TestErrorNeverContainsAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"subscription required"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(t, srv.URL).ReputationLookupBulk(context.Background(), []string{"1.2.3.4"})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), testKey) {
		t.Fatalf("error message leaked the API key: %v", err)
	}
}

func TestKeyFingerprintIsNotKey(t *testing.T) {
	c := newTestClient(t, "https://api.darkapi.io")
	fp := c.KeyFingerprint()
	if fp == "" || strings.Contains(fp, testKey) {
		t.Fatalf("bad fingerprint %q", fp)
	}
	if len(fp) != 64 {
		t.Fatalf("fingerprint length = %d, want 64", len(fp))
	}
}
