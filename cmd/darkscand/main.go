package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/afterdarksys/darkscan/pkg/api/server"
	"github.com/afterdarksys/darkscan/pkg/capa"
	"github.com/afterdarksys/darkscan/pkg/clamav"
	"github.com/afterdarksys/darkscan/pkg/config"
	"github.com/afterdarksys/darkscan/pkg/document"
	"github.com/afterdarksys/darkscan/pkg/heuristics"
	"github.com/afterdarksys/darkscan/pkg/license"
	"github.com/afterdarksys/darkscan/pkg/scanner"
	"github.com/afterdarksys/darkscan/pkg/yara"
	"github.com/spf13/cobra"
)

var (
	configPath  string
	licensePath string
	listenAddr  string
	unixSocket  string
)

var rootCmd = &cobra.Command{
	Use:   "darkscand",
	Short: "DarkScan Daemon - Persistent scanning server",
	RunE:  runServer,
}

func init() {
	defaultConfigPath, _ := config.GetDefaultConfigPath()
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", defaultConfigPath, "Config file path")
	rootCmd.PersistentFlags().StringVar(&licensePath, "license", "/etc/darkscan/license.json", "Commercial license file path")
	rootCmd.PersistentFlags().StringVarP(&listenAddr, "listen", "l", "127.0.0.1:8080", "TCP address to listen on")
	rootCmd.PersistentFlags().StringVarP(&unixSocket, "socket", "s", "/tmp/darkscand.sock", "Unix socket path to listen on")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func loadConfig() (*config.Config, error) {
	if configPath == "" {
		var err error
		configPath, err = config.GetDefaultConfigPath()
		if err != nil {
			return nil, err
		}
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

func runServer(cmd *cobra.Command, args []string) error {
	log.Println("Initializing DarkScan Daemon...")
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	if err := license.Load(licensePath); err != nil {
		log.Printf("Notice: No valid commercial license found at %s. Running in community mode.", licensePath)
	} else {
		log.Printf("Commercial license loaded (Customer: %s)", license.GetActive().Customer)
	}

	// Create root context for the server lifecycle
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize the engine once
	s := scanner.New()

	// Document
	docEngine := document.New()
	s.RegisterEngine(docEngine)
	defer docEngine.Close()

	// ClamAV
	if cfg.ClamAV.Enabled {
		clamavEngine, err := clamav.New(cfg.ClamAV.DatabasePath)
		if err == nil {
			s.RegisterEngine(clamavEngine)
			defer clamavEngine.Close()
			
			// Background Updater Ticker
			if cfg.ClamAV.AutoUpdate && cfg.ClamAV.MirrorURL != "" {
				interval, err := time.ParseDuration(cfg.ClamAV.UpdateInterval)
				if err != nil || interval == 0 {
					interval = 4 * time.Hour
				}

				go func() {
					ticker := time.NewTicker(interval)
					defer ticker.Stop()

					log.Printf("Started ClamAV definition auto-updater (Interval: %s, Mirror: %s)", interval, cfg.ClamAV.MirrorURL)

					for {
						select {
						case <-ticker.C:
							log.Println("Checking for ClamAV definition updates from mirror...")
							err := clamav.UpdateFromMirror(cfg.ClamAV.MirrorURL, cfg.ClamAV.DatabasePath)
							if err != nil {
								log.Printf("Mirror update failed: %v", err)
							} else {
								log.Println("Database updated on disk, triggering engine hot-reload...")
								if reloadErr := s.UpdateEngines(ctx); reloadErr != nil {
									log.Printf("Hot-reload error: %v", reloadErr)
								} else {
									log.Println("Engines successfully hot-reloaded with new definitions.")
								}
							}
						}
					}
				}()
			}
		} else {
			log.Printf("Warning: Failed to initialize ClamAV: %v", err)
		}
	}

	// YARA
	if cfg.YARA.Enabled {
		yaraEngine, err := yara.New(cfg.YARA.RulesPath)
		if err == nil {
			s.RegisterEngine(yaraEngine)
			defer yaraEngine.Close()
		} else {
			log.Printf("Warning: Failed to initialize YARA: %v", err)
		}
	}

	// CAPA
	if cfg.CAPA.Enabled {
		capaEngine, err := capa.New(cfg.CAPA.ExePath, cfg.CAPA.RulesPath)
		if err == nil {
			s.RegisterEngine(capaEngine)
			defer capaEngine.Close()
		} else {
			log.Printf("Warning: Failed to initialize CAPA: %v", err)
		}
	}

	// Heuristics
	heuristicsEngine := heuristics.New()
	s.RegisterEngine(heuristicsEngine)
	defer heuristicsEngine.Close()

	log.Println("Scanning engines initialized and loaded into memory.")

	// Start server
	srv := server.NewServer(s, listenAddr, unixSocket, cfg.Daemon.MaxUploadSizeMB)

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Start()
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errChan:
		cancel() // Cancel context on error
		return fmt.Errorf("server error: %w", err)
	case sig := <-sigChan:
		log.Printf("Received signal %v, initiating graceful shutdown...", sig)
		cancel() // Cancel context on shutdown
		return srv.Stop()
	}
}
