package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"simpleauth/internal/auth"
	"simpleauth/internal/config"
	"simpleauth/internal/handler"
	"simpleauth/internal/store"
	saui "simpleauth/ui"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Printf("simpleauth %s (built %s)\n", Version, BuildTime)
			return
		case "init-config":
			path := "simpleauth.yaml"
			if len(os.Args) > 2 {
				path = os.Args[2]
			}
			if err := config.WriteDefaultConfig(path); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Default config written to %s\n", path)
			return
		}
	}

	for {
		if exit := runServer(); exit {
			break
		}
		log.Println("Restarting SimpleAuth...")
		time.Sleep(500 * time.Millisecond)
	}
}

func runServer() (exit bool) {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Config error: %v", err)
	}

	if cfg.AdminKey == "" {
		cfg.AdminKey = loadOrCreateAdminKey(cfg.DataDir)
	}

	// Open store (checks db.json → env postgres → BoltDB, with fallback)
	s, err := store.OpenSmart(cfg.DataDir, cfg.PostgresURL)
	if err != nil {
		log.Fatalf("Failed to open store: %v", err)
	}
	defer s.Close()

	// Seed default roles from config if store has none
	if len(cfg.DefaultRoles) > 0 {
		existing, _ := s.GetDefaultRoles()
		if len(existing) == 0 {
			s.SetDefaultRoles(cfg.DefaultRoles)
			log.Printf("Default roles set from config: %v", cfg.DefaultRoles)
		}
	}

	// v2: ensure a default app exists, wrapping the existing single-client config.
	ensureDefaultApp(s, cfg)

	// Initialize JWT manager (auto-generates RSA keys on first run)
	jwtMgr, err := auth.NewJWTManager(cfg.DataDir, cfg.JWTIssuer)
	if err != nil {
		log.Fatalf("Failed to initialize JWT manager: %v", err)
	}

	// Create handler
	h := handler.New(cfg, s, jwtMgr, saui.FS(), Version)

	// Set up restart channel
	restartCh := make(chan struct{}, 1)
	h.SetRestartChannel(restartCh)

	// Background goroutines started below are torn down when this returns (on a
	// graceful admin restart) so each restart does not leak a pruner goroutine
	// still pointing at the now-closed store.
	stop := make(chan struct{})
	defer close(stop)

	// Start audit log pruner
	h.StartAuditPruner(stop)

	log.Printf("SimpleAuth %s starting", Version)
	log.Printf("Hostname: %s", cfg.Hostname)
	log.Printf("Data directory: %s", cfg.DataDir)
	if cfg.PostgresURL != "" {
		log.Printf("Database: PostgreSQL")
	} else {
		log.Printf("Database: BoltDB (%s/auth.db)", cfg.DataDir)
	}
	log.Printf("Admin UI: %s/admin", cfg.BasePath)

	// Print access URLs
	if cfg.TLSDisabled {
		log.Printf("Listening:    http://0.0.0.0:%s%s", cfg.Port, cfg.BasePath)
		log.Printf("Admin UI:     http://0.0.0.0:%s%s/admin", cfg.Port, cfg.BasePath)
	} else {
		port := cfg.Port
		portSuffix := ":" + port
		if port == "443" {
			portSuffix = ""
		}
		log.Printf("Access: https://%s%s%s", cfg.Hostname, portSuffix, cfg.BasePath)
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
					log.Printf("Access: https://%s%s%s", ipnet.IP, portSuffix, cfg.BasePath)
				}
			}
		}
	}

	// newHTTPServer applies hardened timeouts to every listener so a slow client
	// cannot hold a connection open indefinitely (Slowloris) and request headers
	// are bounded. Behind a reverse proxy these still backstop a misbehaving proxy.
	newHTTPServer := func(addr string, handler http.Handler) *http.Server {
		return &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    1 << 20, // 1 MiB
		}
	}

	var srv *http.Server
	var redirectSrv *http.Server

	if cfg.TLSDisabled {
		addr := ":" + cfg.Port
		log.Printf("HTTP listening on %s (TLS disabled — reverse proxy mode)", addr)
		srv = newHTTPServer(addr, h)
	} else {
		// Start HTTP → HTTPS redirect server
		if cfg.HTTPPort != "" {
			httpAddr := ":" + cfg.HTTPPort
			httpsPort := cfg.Port
			log.Printf("HTTP redirect :%s → HTTPS :%s", cfg.HTTPPort, httpsPort)
			redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				host := r.Host
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
				target := "https://" + host
				if httpsPort != "443" {
					target += ":" + httpsPort
				}
				target += r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			})
			redirectSrv = newHTTPServer(httpAddr, redirectHandler)
			go func() {
				if err := redirectSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Printf("HTTP redirect server stopped: %v", err)
				}
			}()
		}

		addr := ":" + cfg.Port
		log.Printf("HTTPS listening on %s", addr)
		srv = newHTTPServer(addr, h)
	}

	// Listen for restart signal
	go func() {
		<-restartCh
		log.Println("Graceful shutdown initiated by admin...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		if redirectSrv != nil {
			redirectSrv.Shutdown(ctx)
		}
	}()

	// Start serving
	if cfg.TLSDisabled {
		err = srv.ListenAndServe()
	} else {
		err = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	}

	if err == http.ErrServerClosed {
		// Graceful shutdown — restart
		return false
	}
	if err != nil {
		log.Fatalf("Server failed: %v", err)
	}
	return true
}

func generateAdminKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// loadOrCreateAdminKey returns a stable admin key when none is configured. It
// persists the generated key to <dataDir>/admin.key (0600) so it survives
// restarts instead of being regenerated each boot, and logs the file path
// rather than the secret itself so the key never lands in stdout/log capture.
func loadOrCreateAdminKey(dataDir string) string {
	path := filepath.Join(dataDir, "admin.key")
	if b, err := os.ReadFile(path); err == nil {
		if key := strings.TrimSpace(string(b)); key != "" {
			log.Printf("No admin_key configured — using the persisted key at %s", path)
			return key
		}
	}
	key := generateAdminKey()
	if err := os.WriteFile(path, []byte(key+"\n"), 0600); err != nil {
		log.Printf("WARNING: no admin_key configured and could not persist one to %s: %v — it will change on restart", path, err)
	} else {
		log.Printf("No admin_key configured — generated one and saved it to %s (read it from there; set admin_key/AUTH_ADMIN_KEY to override)", path)
	}
	return key
}

// ensureDefaultApp creates a default app on first v2 start, wrapping the
// existing single-client config (client id, redirect URIs, optional secret) so
// v1 deployments keep working unchanged. No-op if any app already exists.
func ensureDefaultApp(s store.Store, cfg *config.Config) {
	apps, err := s.ListApps()
	if err != nil || len(apps) > 0 {
		return
	}
	appID := cfg.ClientID
	if appID == "" {
		appID = "simpleauth"
	}
	a := &store.App{
		AppID:        appID,
		Name:         "Default",
		Audience:     appID,
		RedirectURIs: cfg.RedirectURIs,
		CreatedAt:    time.Now().UTC(),
	}
	if cfg.ClientSecret != "" {
		if hash, herr := auth.HashPassword(cfg.ClientSecret); herr == nil {
			a.SecretHash = hash
		}
	}
	if err := s.CreateApp(a); err == nil {
		log.Printf("Created default app %q from existing config (v2)", appID)
	}
}
