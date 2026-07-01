package web

import (
	"context"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Server is the long-running WebUI HTTP server. It hosts the SPA-like static
// assets, the JSON API, and the Server-Sent Events stream. Scans are executed
// as `springx scan --jsonl-only` child processes; their stdout JSONL events
// are parsed and forwarded to browsers over SSE (see scanmgr.go).
type Server struct {
	addr    string
	workDir string
	jobTTL  time.Duration
	mgr     *ScanManager
	mux     *http.ServeMux
	srv     *http.Server
	log     *log.Logger
}

// Options configures a Server. Zero values are filled with sensible defaults.
type Options struct {
	Addr    string        // listen address, e.g. "127.0.0.1:8849"
	WorkDir string        // working dir for scan reports; defaults to os.Getwd()
	ExePath string        // path to the springx binary; defaults to os.Executable()
	JobTTL  time.Duration // terminal-job TTL; 0 disables the reaper
	Logger  *log.Logger
	// Builder optionally overrides how scan child processes are constructed;
	// tests inject a fake that emits a canned JSONL stream. Defaults to the
	// real exec.CommandContext-based child.
	Builder CommandBuilder
}

// NewServer builds a Server from options. It wires routes but does not start
// listening; call Start to serve, or Handler to mount the mux elsewhere.
func NewServer(opts Options) (*Server, error) {
	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:8849"
	}
	if opts.WorkDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		opts.WorkDir = wd
	}
	if opts.ExePath == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		opts.ExePath = exe
	}
	if opts.Logger == nil {
		opts.Logger = log.New(os.Stderr, "[web] ", log.LstdFlags|log.Lmsgprefix)
	}
	abs, err := filepath.Abs(opts.WorkDir)
	if err != nil {
		return nil, err
	}
	opts.WorkDir = abs

	mgr := NewScanManager(ScanManagerOptions{
		ExePath: opts.ExePath,
		WorkDir: opts.WorkDir,
		Logger:  opts.Logger,
		Builder: opts.Builder,
	})

	s := &Server{
		addr:    opts.Addr,
		workDir: opts.WorkDir,
		jobTTL:  opts.JobTTL,
		mgr:     mgr,
		mux:     http.NewServeMux(),
		log:     opts.Logger,
	}
	s.registerRoutes()
	return s, nil
}

// registerRoutes wires the static assets, the index page, and the JSON API.
func (s *Server) registerRoutes() {
	assets := assetFS()
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(assets))))
	s.mux.HandleFunc("GET /{$}", s.handleIndex)
	s.mux.HandleFunc("GET /api/health", s.handleHealth)

	// Scan + streaming API.
	s.mux.HandleFunc("POST /api/scan", s.handleStartScan)
	s.mux.HandleFunc("GET /api/scans", s.handleListScans)
	s.mux.HandleFunc("GET /api/events", s.handleEvents)
	s.mux.HandleFunc("POST /api/scan/{jobID}/cancel", s.handleCancelScan)

	// Reports API (path-restricted to reports/data).
	s.mux.HandleFunc("GET /api/reports", s.handleListReports)
	s.mux.HandleFunc("GET /api/reports/{name}", s.handleGetReport)

	// POC templates API: query status or pull official nuclei-templates.
	s.mux.HandleFunc("GET /api/templates", s.handleGetTemplates)
	s.mux.HandleFunc("POST /api/templates/pull", s.handlePullTemplates)
}

// handleIndex serves the embedded SPA shell.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(assetFS(), "index.html")
	if err != nil {
		http.Error(w, "index not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

// handleHealth is a liveness probe.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// Handler returns the configured mux, for testing or composition.
func (s *Server) Handler() http.Handler { return s.mux }

// Addr returns the configured listen address.
func (s *Server) Addr() string { return s.addr }

// Start serves HTTP until ctx is cancelled or the listener fails. It blocks.
func (s *Server) Start(ctx context.Context) error {
	// Start the terminal-job TTL reaper (no-op if JobTTL <= 0). It stops with ctx.
	s.mgr.StartReaper(ctx, s.jobTTL)

	s.srv = &http.Server{
		Addr:              s.addr,
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		s.log.Printf("WebUI listening on http://%s (work-dir=%s)", s.addr, s.workDir)
		if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
