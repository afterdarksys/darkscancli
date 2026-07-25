package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/darkscan/pkg/scanner"
	"github.com/afterdarksys/darkscan/pkg/stego"
	"github.com/afterdarksys/darkscan/pkg/store"
	"github.com/afterdarksys/darkscan/pkg/vfs/local"
	"github.com/afterdarksys/darkscan/pkg/vfs/nfs"
	"github.com/afterdarksys/darkscan/pkg/vfs/ntfs"
	"github.com/afterdarksys/darkscan/pkg/vfs/s3"
)

type Server struct {
	scanner        *scanner.Scanner
	listenAddr     string
	unixSocket     string
	httpServer     *http.Server
	unixListener   net.Listener
	tcpListener    net.Listener
	wg             sync.WaitGroup
	doneChan       chan struct{}
	maxUploadBytes int64
	startTime      time.Time
	store          *store.Store
	authToken      string
	scanRoot       string
	tlsCert        string
	tlsKey         string
}

func NewServer(s *scanner.Scanner, listenAddr, unixSocket string, maxUploadMB int) *Server {
	maxUploadBytes := int64(maxUploadMB) * 1024 * 1024
	if maxUploadBytes <= 0 {
		maxUploadBytes = 500 * 1024 * 1024 // Default 500MB
	}
	return &Server{
		scanner:        s,
		listenAddr:     listenAddr,
		unixSocket:     unixSocket,
		doneChan:       make(chan struct{}),
		maxUploadBytes: maxUploadBytes,
		startTime:      time.Now(),
	}
}

// WithStore assigns a scanner store to the server
func (s *Server) WithStore(st *store.Store) *Server {
	s.store = st
	return s
}

// WithAuthToken secures the server API with a bearer token
func (s *Server) WithAuthToken(token string) *Server {
	s.authToken = token
	return s
}

// WithScanRoot restricts /scan/local to a specific directory branch
func (s *Server) WithScanRoot(root string) *Server {
	s.scanRoot = root
	return s
}

// WithTLS enables verified HTTPS on the TCP listener.
func (s *Server) WithTLS(certFile, keyFile string) *Server {
	s.tlsCert, s.tlsKey = certFile, keyFile
	return s
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			s.sendError(w, "Unauthorized: missing or invalid authorization header", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.authToken)) != 1 {
			s.sendError(w, "Unauthorized: invalid token", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func (s *Server) Start() error {
	if s.authToken == "" {
		return fmt.Errorf("daemon bearer token is required")
	}
	if s.scanRoot == "" {
		return fmt.Errorf("daemon scan root is required")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", s.handlePing)
	mux.HandleFunc("/status", s.requireAuth(s.handleStatus))
	mux.HandleFunc("/update", s.requireAuth(s.handleUpdate))
	mux.HandleFunc("/scan/local", s.requireAuth(s.handleScanLocal))
	mux.HandleFunc("/scan/stream", s.requireAuth(s.handleScanStream))
	mux.HandleFunc("/stego/analyze", s.requireAuth(s.handleStegoAnalyze))
	mux.HandleFunc("/hashstore/check", s.requireAuth(s.handleHashCheck))
	mux.HandleFunc("/hashstore/update", s.requireAuth(s.handleHashUpdate))

	s.httpServer = &http.Server{
		Handler: mux,
	}

	errChan := make(chan error, 2)

	// Start Unix Socket Listener
	if s.unixSocket != "" {
		if _, err := os.Stat(s.unixSocket); err == nil {
			os.Remove(s.unixSocket)
		}
		unixL, err := net.Listen("unix", s.unixSocket)
		if err != nil {
			return err
		}
		s.unixListener = unixL

		// Set permissions for local CLI access (0660 = owner and group can read/write)
		// More secure than 0666 which allows any user
		os.Chmod(s.unixSocket, 0660)

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			log.Printf("Listening on Unix socket: %s", s.unixSocket)
			if err := s.httpServer.Serve(s.unixListener); err != nil && err != http.ErrServerClosed {
				errChan <- err
			}
		}()
	}

	// Start TCP Listener
	if s.listenAddr != "" {
		if s.tlsCert == "" || s.tlsKey == "" {
			return fmt.Errorf("TCP listener requires --tls-cert and --tls-key")
		}
		tcpL, err := net.Listen("tcp", s.listenAddr)
		if err != nil {
			return err
		}
		certificate, err := tls.LoadX509KeyPair(s.tlsCert, s.tlsKey)
		if err != nil {
			tcpL.Close()
			return fmt.Errorf("load TLS certificate: %w", err)
		}
		s.tcpListener = tls.NewListener(tcpL, &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certificate},
		})

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			log.Printf("Listening on TCP address: %s", s.listenAddr)
			if err := s.httpServer.Serve(s.tcpListener); err != nil && err != http.ErrServerClosed {
				errChan <- err
			}
		}()
	}

	// Wait for error or shutdown
	select {
	case err := <-errChan:
		return err
	case <-s.doneChan:
		return nil
	}
}

func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Signal Start() to return
	close(s.doneChan)

	if s.unixSocket != "" {
		os.Remove(s.unixSocket)
	}

	if s.httpServer != nil {
		err := s.httpServer.Shutdown(ctx)
		s.wg.Wait()
		return err
	}
	return nil
}

type ScanLocalRequest struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
}

type ScanResponse struct {
	Success  bool                  `json:"success"`
	Error    string                `json:"error,omitempty"`
	Duration string                `json:"duration,omitempty"`
	Results  []*scanner.ScanResult `json:"results,omitempty"`
}

type StatusResponse struct {
	Status  string         `json:"status"`
	Engines []EngineStatus `json:"engines"`
	Uptime  string         `json:"uptime"`
	Version string         `json:"version"`
}

type EngineStatus struct {
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	Version    string `json:"version,omitempty"`
	LastUpdate string `json:"last_update,omitempty"`
}

type UpdateResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

type StegoAnalyzeRequest struct {
	Path string `json:"path"`
}

type StegoAnalyzeResponse struct {
	Success  bool            `json:"success"`
	Error    string          `json:"error,omitempty"`
	Analysis *stego.Analysis `json:"analysis,omitempty"`
}

type HashCheckRequest struct {
	SHA256 string `json:"sha256"`
}

type HashCheckResponse struct {
	Success bool                  `json:"success"`
	Error   string                `json:"error,omitempty"`
	Found   bool                  `json:"found"`
	Entry   *store.HashCacheEntry `json:"entry,omitempty"`
}

type HashUpdateRequest struct {
	Entry store.HashCacheEntry `json:"entry"`
}

type HashUpdateResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	engines := []EngineStatus{}
	// Note: This is a simplified version showing the scanner is running
	// In a future enhancement, we could expose engine details via scanner API
	engines = append(engines, EngineStatus{
		Name:    "Scanner",
		Enabled: true,
	})

	status := StatusResponse{
		Status:  "running",
		Engines: engines,
		Uptime:  time.Since(s.startTime).String(),
		Version: "1.0.0", // TODO: Get from build info
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		log.Printf("Failed to encode status response: %v", err)
	}
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Println("Manual update triggered via API")

	// Trigger engine updates
	ctx := r.Context()
	if err := s.scanner.UpdateEngines(ctx); err != nil {
		resp := UpdateResponse{
			Success: false,
			Error:   fmt.Sprintf("Update failed: %v", err),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := UpdateResponse{
		Success: true,
		Message: "Engines updated successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to encode update response: %v", err)
	}
}

func (s *Server) handleScanLocal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanLocalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if req.Path == "" {
		s.sendError(w, "Path is required", http.StatusBadRequest)
		return
	}

	if strings.Contains(req.Path, "://") {
		s.sendError(w, "Remote VFS paths are not accepted by /scan/local", http.StatusBadRequest)
		return
	}
	if s.scanRoot != "" {
		absPath, err := filepath.EvalSymlinks(req.Path)
		if err != nil {
			s.sendError(w, "Invalid path", http.StatusBadRequest)
			return
		}

		absRoot, err := filepath.EvalSymlinks(s.scanRoot)
		if err != nil {
			s.sendError(w, "Server configuration error: invalid scan root", http.StatusInternalServerError)
			return
		}

		relative, err := filepath.Rel(absRoot, absPath)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			s.sendError(w, "Access Denied: Path outside allowed scan root", http.StatusForbidden)
			return
		}

		req.Path = absPath
	}

	log.Printf("Performing local scan of path: %s (recursive: %v)", req.Path, req.Recursive)

	start := time.Now()
	ctx := r.Context()

	var results []*scanner.ScanResult
	var err error

	scanClient := s.scanner

	if strings.HasPrefix(req.Path, "s3://") {
		parts := strings.SplitN(strings.TrimPrefix(req.Path, "s3://"), "/", 2)
		bucket := parts[0]
		key := ""
		if len(parts) > 1 {
			key = parts[1]
		}
		fs, err := s3.New(context.Background(), bucket)
		if err != nil {
			s.sendError(w, "Failed to setup s3 vfs: "+err.Error(), http.StatusInternalServerError)
			return
		}
		scanClient = s.scanner.WithVFS(fs)
		req.Path = key
	} else if strings.HasPrefix(req.Path, "nfs://") {
		parts := strings.SplitN(strings.TrimPrefix(req.Path, "nfs://"), "/", 2)
		host := parts[0]
		mount := "/"
		if len(parts) > 1 {
			mount = "/" + parts[1]
		}
		fs, err := nfs.New(host, mount)
		if err != nil {
			s.sendError(w, "Failed to setup nfs vfs: "+err.Error(), http.StatusInternalServerError)
			return
		}
		scanClient = s.scanner.WithVFS(fs)
		req.Path = "/"
	} else if strings.HasPrefix(req.Path, "ntfs://") {
		imgPath := strings.TrimPrefix(req.Path, "ntfs://")
		part, err := local.NewPartition(imgPath)
		if err != nil {
			s.sendError(w, "Failed to open ntfs source: "+err.Error(), http.StatusInternalServerError)
			return
		}
		fs, err := ntfs.New(part)
		if err != nil {
			s.sendError(w, "Failed to setup ntfs vfs: "+err.Error(), http.StatusInternalServerError)
			return
		}
		scanClient = s.scanner.WithVFS(fs)
		req.Path = "/"
	} else {
		scanClient = s.scanner.WithVFS(local.New())
	}

	var info os.FileInfo
	if scanClient.FS != nil {
		info, err = scanClient.FS.Stat(req.Path)
	} else {
		info, err = os.Stat(req.Path)
	}

	if err != nil {
		s.sendError(w, "File not found or inaccessible: "+err.Error(), http.StatusNotFound)
		return
	}

	if info.IsDir() {
		results, err = scanClient.ScanDirectory(ctx, req.Path, req.Recursive)
	} else {
		results, err = scanClient.ScanFile(ctx, req.Path)
	}

	if err != nil {
		s.sendError(w, "Scan failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.sendResponse(w, results, time.Since(start))
}

func (s *Server) handleScanStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate Content-Type
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/octet-stream" && contentType != "" {
		s.sendError(w, "Content-Type must be application/octet-stream", http.StatusBadRequest)
		return
	}

	// Limit request body size
	limitedReader := http.MaxBytesReader(w, r.Body, s.maxUploadBytes)

	// Create a temp file to store the stream buffer
	tmpFile, err := os.CreateTemp("", "darkscand-stream-*.tmp")
	if err != nil {
		s.sendError(w, "Failed to create temp file", http.StatusInternalServerError)
		return
	}
	tmpPath := tmpFile.Name()

	_, err = io.Copy(tmpFile, limitedReader)
	tmpFile.Close() // Close before scanning to flush buffers

	if err != nil {
		os.Remove(tmpPath)
		s.sendError(w, "Failed to read stream upload", http.StatusInternalServerError)
		return
	}

	log.Printf("Performing stream scan (saved to %s)", tmpPath)

	start := time.Now()
	results, err := s.scanner.ScanFile(r.Context(), tmpPath)

	// Clean up temp file after scan completes
	os.Remove(tmpPath)

	if err != nil {
		s.sendError(w, "Scan failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Scrub the tmpfile path from the response and replace with "stream"
	for _, res := range results {
		if strings.HasPrefix(res.FilePath, os.TempDir()) {
			res.FilePath = "stream_upload"
		}
	}

	s.sendResponse(w, results, time.Since(start))
}

func (s *Server) handleStegoAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req StegoAnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(StegoAnalyzeResponse{Success: false, Error: "Invalid JSON payload"})
		return
	}

	if req.Path == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(StegoAnalyzeResponse{Success: false, Error: "Path is required"})
		return
	}

	// Apply scanRoot restriction for local paths
	if s.scanRoot != "" && !strings.HasPrefix(req.Path, "s3://") && !strings.HasPrefix(req.Path, "nfs://") && !strings.HasPrefix(req.Path, "ntfs://") {
		absPath, err := filepath.EvalSymlinks(req.Path)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(StegoAnalyzeResponse{Success: false, Error: "Invalid path"})
			return
		}

		absRoot, err := filepath.EvalSymlinks(s.scanRoot)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(StegoAnalyzeResponse{Success: false, Error: "Server configuration error"})
			return
		}

		if !strings.HasPrefix(absPath, absRoot+string(filepath.Separator)) && absPath != absRoot {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(StegoAnalyzeResponse{Success: false, Error: "Access Denied: Path outside allowed scan root"})
			return
		}

		req.Path = absPath
	}

	analyzer := stego.NewAnalyzer()
	analysis, err := analyzer.AnalyzeFile(req.Path)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(StegoAnalyzeResponse{Success: false, Error: err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(StegoAnalyzeResponse{
		Success:  true,
		Analysis: analysis,
	}); err != nil {
		log.Printf("Failed to encode stego response: %v", err)
	}
}

func (s *Server) handleHashCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.store == nil {
		s.sendError(w, "HashStore is not configured on this daemon", http.StatusNotImplemented)
		return
	}

	var req HashCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(HashCheckResponse{Success: false, Error: "Invalid JSON payload"})
		return
	}

	entry, found := s.store.CheckHashCache(req.SHA256)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(HashCheckResponse{
		Success: true,
		Found:   found,
		Entry:   entry,
	}); err != nil {
		log.Printf("Failed to encode hash check response: %v", err)
	}
}

func (s *Server) handleHashUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.store == nil {
		s.sendError(w, "HashStore is not configured on this daemon", http.StatusNotImplemented)
		return
	}

	var req HashUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(HashUpdateResponse{Success: false, Error: "Invalid JSON payload"})
		return
	}

	if err := s.store.UpdateHashCache(req.Entry); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(HashUpdateResponse{Success: false, Error: err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(HashUpdateResponse{
		Success: true,
	}); err != nil {
		log.Printf("Failed to encode hash update response: %v", err)
	}
}

func (s *Server) sendError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(ScanResponse{Success: false, Error: msg}); err != nil {
		log.Printf("Failed to encode error response: %v", err)
	}
}

func (s *Server) sendResponse(w http.ResponseWriter, results []*scanner.ScanResult, duration time.Duration) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(ScanResponse{
		Success:  true,
		Duration: duration.String(),
		Results:  results,
	}); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}
