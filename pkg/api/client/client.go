package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/afterdarksys/darkscan/pkg/api/server"
	"github.com/afterdarksys/darkscan/pkg/scanner"
)

type Client struct {
	httpClient *http.Client
	baseURL    string // Can be unix:// or http://
}

// NewClient attempts to discover a daemon.
// It returns a non-nil client if a daemon is found and responsive.
func NewClient(configDaemonURL string, unixSocket string, requestTimeout, connectTimeout time.Duration) (*Client, error) {
	if requestTimeout == 0 {
		requestTimeout = 1 * time.Hour
	}
	if connectTimeout == 0 {
		connectTimeout = 3 * time.Second
	}

	// Try config daemon first
	if configDaemonURL != "" {
		httpClient := &http.Client{Timeout: requestTimeout}
		if checkHealth(configDaemonURL, connectTimeout) {
			return &Client{
				baseURL:    configDaemonURL,
				httpClient: httpClient,
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
			Transport: transport,
			Timeout:   requestTimeout,
		}

		// Use http://localhost as a dummy host since transport overwrites it anyway
		if checkHealth("http://localhost", connectTimeout) {
			return &Client{
				baseURL:    "http://localhost",
				httpClient: unixClient,
			}, nil
		}
	}

	return nil, fmt.Errorf("no darkscand daemon discovered at %s or unix:%s", configDaemonURL, unixSocket)
}

func checkHealth(url string, timeout time.Duration) bool {
	httpClient := &http.Client{Timeout: timeout}
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
