package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/darkscan/pkg/scanner"
	"github.com/afterdarksys/darkscan/pkg/vfs/local"
	"github.com/afterdarksys/darkscan/pkg/vfs/nfs"
	"github.com/afterdarksys/darkscan/pkg/vfs/ntfs"
	"github.com/afterdarksys/darkscan/pkg/vfs/s3"
)

type Server struct {
	scanner         *scanner.Scanner
	listenAddr      string
	unixSocket      string
	httpServer      *http.Server
	unixListener    net.Listener
	tcpListener     net.Listener
	wg              sync.WaitGroup
	doneChan        chan struct{}
	maxUploadBytes  int64
	startTime       time.Time
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

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", s.handlePing)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/update", s.handleUpdate)
	mux.HandleFunc("/scan/local", s.handleScanLocal)
	mux.HandleFunc("/scan/stream", s.handleScanStream)

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
		tcpL, err := net.Listen("tcp", s.listenAddr)
		if err != nil {
			return err
		}
		s.tcpListener = tcpL
		
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
	Status    string            `json:"status"`
	Engines   []EngineStatus    `json:"engines"`
	Uptime    string            `json:"uptime"`
	Version   string            `json:"version"`
}

type EngineStatus struct {
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Version   string `json:"version,omitempty"`
	LastUpdate string `json:"last_update,omitempty"`
}

type UpdateResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
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
