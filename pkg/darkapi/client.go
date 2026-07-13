// Package darkapi is a client for the DarkAPI.io threat-intelligence API.
//
// It exposes hash/domain/IP lookups, threat-feed listing, reputation checks,
// software supply-chain (package) checks and identity-exposure lookups over the
// public REST API at https://api.darkapi.io. Every request is authenticated with
// an X-API-Key header.
//
// Threats: protects against leaking credentials in logs/errors (the API key is
// never logged or embedded in errors; if it must be referenced a SHA-256
// fingerprint is used), unbounded response bodies (every response is read
// through a 10 MB io.LimitReader), and plaintext transport (non-https base URLs
// are rejected unless the host is localhost/127.0.0.1, and Go's default TLS
// verification is always used — never InsecureSkipVerify). It does NOT protect
// against a compromised api.darkapi.io returning malicious-but-well-formed data.
package darkapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/afterdarksys/darkscan/pkg/config"
)

// Version is used in the User-Agent header. DarkScan has no shared version
// package, so this mirrors the CLI's advertised version.
const Version = "1.0.0"

const (
	defaultBaseURL   = "https://api.darkapi.io"
	requestTimeout   = 30 * time.Second
	maxResponseBytes = 10 * 1024 * 1024 // 10 MB cap on any response body
	maxBulkItems     = 100
)

// Sentinel errors so callers can branch on transport-level failures with
// errors.Is without depending on concrete status codes.
var (
	// ErrUnauthorized is returned (wrapped) for HTTP 401 responses.
	ErrUnauthorized = errors.New("darkapi: unauthorized")
	// ErrRateLimited is returned (wrapped) for HTTP 429 responses.
	ErrRateLimited = errors.New("darkapi: rate limited")
)

// APIError describes a non-2xx response from the API. The Message is taken from
// the JSON error body and never contains the caller's API key.
type APIError struct {
	StatusCode int
	Message    string
	// RetryAfter is the Retry-After value in seconds for 429 responses (0 if absent).
	RetryAfter int
}

func (e *APIError) Error() string {
	if e.StatusCode == http.StatusTooManyRequests && e.RetryAfter > 0 {
		return fmt.Sprintf("darkapi: %d %s (retry after %ds)", e.StatusCode, e.Message, e.RetryAfter)
	}
	return fmt.Sprintf("darkapi: %d %s", e.StatusCode, e.Message)
}

// Unwrap maps well-known status codes onto sentinel errors so that
// errors.Is(err, ErrUnauthorized) / errors.Is(err, ErrRateLimited) work.
func (e *APIError) Unwrap() error {
	switch e.StatusCode {
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusTooManyRequests:
		return ErrRateLimited
	}
	return nil
}

// Client is a DarkAPI.io API client. Construct it with NewClient.
type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
	userAgent  string
}

// Feed is one entry in the threat-feed catalogue. Unknown fields are ignored.
type Feed struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type,omitempty"`
	Count       int    `json:"count,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
	URL         string `json:"url,omitempty"`
}

// FeedList is the typed result of ListFeeds. Raw carries the untouched response
// body for full-fidelity pretty-printing.
type FeedList struct {
	Feeds []Feed          `json:"feeds"`
	Raw   json.RawMessage `json:"-"`
}

// PackageRef identifies a package in an ecosystem for a supply-chain check.
type PackageRef struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
}

// PackageCheckResult is the typed result of a package check. Fields that are
// absent from the response stay at their zero value; Raw carries the full body.
type PackageCheckResult struct {
	Ecosystem string          `json:"ecosystem,omitempty"`
	Name      string          `json:"name,omitempty"`
	Version   string          `json:"version,omitempty"`
	Malicious bool            `json:"malicious,omitempty"`
	Typosquat bool            `json:"typosquat,omitempty"`
	Risk      string          `json:"risk,omitempty"`
	Reason    string          `json:"reason,omitempty"`
	Raw       json.RawMessage `json:"-"`
}

// NewClient builds a client from the DarkAPI configuration block. It returns an
// error if the API key is empty, or if the base URL is non-https for a
// non-loopback host. The HTTP client uses Go's default TLS verification.
func NewClient(cfg config.DarkAPIConfig) (*Client, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("darkapi: api key is required")
	}

	base := strings.TrimSpace(cfg.BaseURL)
	if base == "" {
		base = defaultBaseURL
	}
	base = strings.TrimRight(base, "/")

	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("darkapi: invalid base url: %w", err)
	}
	if u.Scheme != "https" {
		host := u.Hostname()
		if !(u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1")) {
			return nil, fmt.Errorf("darkapi: refusing non-https base url %q", base)
		}
	}

	return &Client{
		httpClient: &http.Client{Timeout: requestTimeout},
		baseURL:    base,
		apiKey:     cfg.APIKey,
		userAgent:  "darkscan/" + Version,
	}, nil
}

// KeyFingerprint returns the SHA-256 fingerprint of the API key. Use this rather
// than the key itself if a key must ever be referenced in logs.
func (c *Client) KeyFingerprint() string {
	sum := sha256.Sum256([]byte(c.apiKey))
	return hex.EncodeToString(sum[:])
}

// do performs a request and returns the response body bytes. Any transport,
// size or status error returns an error (fail closed — never partial success).
func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("darkapi: encode request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("darkapi: build request: %w", err)
	}
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("darkapi: request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("darkapi: read response: %w", err)
	}
	if int64(len(data)) > maxResponseBytes {
		return nil, fmt.Errorf("darkapi: response exceeds %d byte limit", maxResponseBytes)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseAPIError(resp, data)
	}
	return data, nil
}

func parseAPIError(resp *http.Response, body []byte) error {
	var payload struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	msg := ""
	if json.Unmarshal(body, &payload) == nil {
		switch {
		case payload.Error != "":
			msg = payload.Error
		case payload.Message != "":
			msg = payload.Message
		}
	}
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}

	apiErr := &APIError{StatusCode: resp.StatusCode, Message: msg}
	if resp.StatusCode == http.StatusTooManyRequests {
		if ra := strings.TrimSpace(resp.Header.Get("Retry-After")); ra != "" {
			if secs, err := strconv.Atoi(ra); err == nil {
				apiErr.RetryAfter = secs
			}
		}
	}
	return apiErr
}

// LookupHash performs GET /v1/hash/<hash>.
func (c *Client) LookupHash(ctx context.Context, hash string) (json.RawMessage, error) {
	b, err := c.do(ctx, http.MethodGet, "/v1/hash/"+url.PathEscape(hash), nil)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// LookupDomain performs GET /v1/domain/<domain>.
func (c *Client) LookupDomain(ctx context.Context, domain string) (json.RawMessage, error) {
	b, err := c.do(ctx, http.MethodGet, "/v1/domain/"+url.PathEscape(domain), nil)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// LookupIP performs GET /v1/ip/<ip>.
func (c *Client) LookupIP(ctx context.Context, ip string) (json.RawMessage, error) {
	b, err := c.do(ctx, http.MethodGet, "/v1/ip/"+url.PathEscape(ip), nil)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// ListFeeds performs GET /v1/feeds and returns the typed feed catalogue.
func (c *Client) ListFeeds(ctx context.Context) (*FeedList, error) {
	b, err := c.do(ctx, http.MethodGet, "/v1/feeds", nil)
	if err != nil {
		return nil, err
	}

	fl := &FeedList{Raw: json.RawMessage(b)}
	// Accept both {"feeds":[...]} and a bare [...] array.
	if err := json.Unmarshal(b, fl); err != nil {
		var arr []Feed
		if err2 := json.Unmarshal(b, &arr); err2 != nil {
			return nil, fmt.Errorf("darkapi: decode feeds: %w", err)
		}
		fl.Feeds = arr
	} else if fl.Feeds == nil {
		var arr []Feed
		if json.Unmarshal(b, &arr) == nil {
			fl.Feeds = arr
		}
	}
	return fl, nil
}

// GetFeed performs GET /v1/feeds/<name> and returns the raw feed payload.
func (c *Client) GetFeed(ctx context.Context, name string) (json.RawMessage, error) {
	b, err := c.do(ctx, http.MethodGet, "/v1/feeds/"+url.PathEscape(name), nil)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// ReputationLookup performs POST /v1/reputation/lookup. typeHint is optional and
// may be empty.
func (c *Client) ReputationLookup(ctx context.Context, indicator, typeHint string) (json.RawMessage, error) {
	body := map[string]string{"indicator": indicator}
	if typeHint != "" {
		body["type"] = typeHint
	}
	b, err := c.do(ctx, http.MethodPost, "/v1/reputation/lookup", body)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// ReputationLookupBulk performs POST /v1/reputation/lookup/bulk (paid tier).
func (c *Client) ReputationLookupBulk(ctx context.Context, indicators []string) (json.RawMessage, error) {
	if len(indicators) == 0 {
		return nil, errors.New("darkapi: no indicators supplied")
	}
	if len(indicators) > maxBulkItems {
		return nil, fmt.Errorf("darkapi: too many indicators (%d > %d)", len(indicators), maxBulkItems)
	}
	b, err := c.do(ctx, http.MethodPost, "/v1/reputation/lookup/bulk", map[string][]string{"indicators": indicators})
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// PackageCheck performs POST /v1/packages/check for a single package.
func (c *Client) PackageCheck(ctx context.Context, ref PackageRef) (*PackageCheckResult, error) {
	b, err := c.do(ctx, http.MethodPost, "/v1/packages/check", ref)
	if err != nil {
		return nil, err
	}
	var res PackageCheckResult
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, fmt.Errorf("darkapi: decode package result: %w", err)
	}
	res.Raw = json.RawMessage(b)
	return &res, nil
}

// PackageCheckBulk performs POST /v1/packages/check/bulk for many packages.
func (c *Client) PackageCheckBulk(ctx context.Context, refs []PackageRef) (json.RawMessage, error) {
	if len(refs) == 0 {
		return nil, errors.New("darkapi: no packages supplied")
	}
	if len(refs) > maxBulkItems {
		return nil, fmt.Errorf("darkapi: too many packages (%d > %d)", len(refs), maxBulkItems)
	}
	b, err := c.do(ctx, http.MethodPost, "/v1/packages/check/bulk", map[string][]PackageRef{"packages": refs})
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// IdentityExposure performs POST /v1/identity/exposure for a breach/PII lookup.
func (c *Client) IdentityExposure(ctx context.Context, value string) (json.RawMessage, error) {
	b, err := c.do(ctx, http.MethodPost, "/v1/identity/exposure", map[string]string{"value": value})
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}
