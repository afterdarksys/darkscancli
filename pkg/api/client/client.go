package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/afterdarksys/darkscan/pkg/api/server"
	"github.com/afterdarksys/darkscan/pkg/scanner"
	"github.com/afterdarksys/darkscan/pkg/stego"
	"github.com/afterdarksys/darkscan/pkg/store"
)

type Client struct {
	httpClient *http.Client
	baseURL    string // Can be unix:// or http://
	authToken  string
}

// authTransport is an http.RoundTripper that injects the authorization token
type authTransport struct {
	transport http.RoundTripper
	token     string
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.token != "" {
		req.Header.Set("Authorization", "Bearer "+t.token)
	}
	tr := t.transport
	if tr == nil {
		tr = http.DefaultTransport
	}
	return tr.RoundTrip(req)
}

// NewClient attempts to discover a daemon.
// It returns a non-nil client if a daemon is found and responsive.
func NewClient(configDaemonURL string, unixSocket string, authToken string, requestTimeout, connectTimeout time.Duration) (*Client, error) {
	if authToken == "" {
		return nil, fmt.Errorf("daemon bearer token is required")
	}
	if requestTimeout == 0 {
		requestTimeout = 1 * time.Hour
	}
	if connectTimeout == 0 {
		connectTimeout = 3 * time.Second
	}

	// Try config daemon first
	if configDaemonURL != "" {
		parsed, err := url.Parse(configDaemonURL)
		if err != nil || parsed.Hostname() == "" {
			return nil, fmt.Errorf("invalid daemon endpoint")
		}
		loopback := parsed.Hostname() == "localhost" ||
			parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1"
		if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback) {
			return nil, fmt.Errorf("remote daemon endpoint must use HTTPS")
		}
		if parsed.User != nil && (strings.Contains(parsed.User.String(), "@") || parsed.User.String() != "") {
			return nil, fmt.Errorf("daemon endpoint must not contain credentials")
		}
		httpClient := &http.Client{
			Transport: &authTransport{token: authToken},
			Timeout:   requestTimeout,
		}
		if checkHealth(configDaemonURL, authToken, connectTimeout) {
			return &Client{
				baseURL:    configDaemonURL,
				httpClient: httpClient,
				authToken:  authToken,
			}, nil
		}
	}

	// Try local Unix socket
	if unixSocket == "" {
		unixSocket = "/tmp/darkscand.sock"
	}

	if _, err := os.Stat(unixSocket); err == nil {
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", unixSocket)
			},
		}

		unixClient := &http.Client{
			Transport: &authTransport{transport: transport, token: authToken},
			Timeout:   requestTimeout,
		}

		// Use http://localhost as a dummy host since transport overwrites it anyway
		if checkHealth("http://localhost", authToken, connectTimeout) {
			return &Client{
				baseURL:    "http://localhost",
				httpClient: unixClient,
				authToken:  authToken,
			}, nil
		}
	}

	return nil, fmt.Errorf("no darkscand daemon discovered at %s or unix:%s", configDaemonURL, unixSocket)
}

func checkHealth(url string, token string, timeout time.Duration) bool {
	httpClient := &http.Client{
		Transport: &authTransport{token: token},
		Timeout:   timeout,
	}
	resp, err := httpClient.Get(url + "/ping")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// ScanLocal asks the daemon to scan a file path local to the daemon's machine
func (c *Client) ScanLocal(path string, recursive bool) ([]*scanner.ScanResult, error) {
	reqBody := server.ScanLocalRequest{
		Path:      path,
		Recursive: recursive,
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+"/scan/local", "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("daemon connection error: %w", err)
	}
	defer resp.Body.Close()

	return c.parseResponse(resp)
}

// ScanStream uploads the file bytes to the daemon for scanning
func (c *Client) ScanStream(path string) ([]*scanner.ScanResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	resp, err := c.httpClient.Post(c.baseURL+"/scan/stream", "application/octet-stream", file)
	if err != nil {
		return nil, fmt.Errorf("daemon connection error: %w", err)
	}
	defer resp.Body.Close()

	return c.parseResponse(resp)
}

func (c *Client) parseResponse(resp *http.Response) ([]*scanner.ScanResult, error) {
	var scanResp server.ScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&scanResp); err != nil {
		return nil, fmt.Errorf("failed to decode daemon response: %w", err)
	}

	if !scanResp.Success {
		return nil, fmt.Errorf("daemon returned error: %s", scanResp.Error)
	}

	return scanResp.Results, nil
}

// GetStatus retrieves the daemon status
func (c *Client) GetStatus() (*server.StatusResponse, error) {
	resp, err := c.httpClient.Get(c.baseURL + "/status")
	if err != nil {
		return nil, fmt.Errorf("daemon connection error: %w", err)
	}
	defer resp.Body.Close()

	var status server.StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode status response: %w", err)
	}

	return &status, nil
}

// TriggerUpdate triggers a manual update of the daemon's scanning engines
func (c *Client) TriggerUpdate() error {
	resp, err := c.httpClient.Post(c.baseURL+"/update", "application/json", nil)
	if err != nil {
		return fmt.Errorf("daemon connection error: %w", err)
	}
	defer resp.Body.Close()

	var updateResp server.UpdateResponse
	if err := json.NewDecoder(resp.Body).Decode(&updateResp); err != nil {
		return fmt.Errorf("failed to decode update response: %w", err)
	}

	if !updateResp.Success {
		return fmt.Errorf("update failed: %s", updateResp.Error)
	}

	return nil
}

// AnalyzeStego analyzes a file for steganography via the daemon
func (c *Client) AnalyzeStego(path string) (*stego.Analysis, error) {
	reqBody := server.StegoAnalyzeRequest{
		Path: path,
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+"/stego/analyze", "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("daemon connection error: %w", err)
	}
	defer resp.Body.Close()

	var stegoResp server.StegoAnalyzeResponse
	if err := json.NewDecoder(resp.Body).Decode(&stegoResp); err != nil {
		return nil, fmt.Errorf("failed to decode daemon response: %w", err)
	}

	if !stegoResp.Success {
		return nil, fmt.Errorf("daemon returned error: %s", stegoResp.Error)
	}

	return stegoResp.Analysis, nil
}

// CheckHash queries the daemon's HashStore for previously seen file hashes
func (c *Client) CheckHash(sha256 string) (*store.HashCacheEntry, bool, error) {
	reqBody := server.HashCheckRequest{
		SHA256: sha256,
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, false, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+"/hashstore/check", "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return nil, false, fmt.Errorf("daemon connection error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotImplemented {
		return nil, false, fmt.Errorf("daemon does not have hashstore configured")
	}

	var hashResp server.HashCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&hashResp); err != nil {
		return nil, false, fmt.Errorf("failed to decode daemon response: %w", err)
	}

	if !hashResp.Success {
		return nil, false, fmt.Errorf("daemon returned error: %s", hashResp.Error)
	}

	return hashResp.Entry, hashResp.Found, nil
}

// UpdateHashCache tells the daemon to cache a scan result
func (c *Client) UpdateHashCache(entry store.HashCacheEntry) error {
	reqBody := server.HashUpdateRequest{
		Entry: entry,
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+"/hashstore/update", "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("daemon connection error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotImplemented {
		return fmt.Errorf("daemon does not have hashstore configured")
	}

	var hashResp server.HashUpdateResponse
	if err := json.NewDecoder(resp.Body).Decode(&hashResp); err != nil {
		return fmt.Errorf("failed to decode daemon response: %w", err)
	}

	if !hashResp.Success {
		return fmt.Errorf("daemon returned error: %s", hashResp.Error)
	}

	return nil
}
