// Package server exposes the fingerprint engine over HTTP.
//
// Endpoints:
//
//	POST /fingerprint  batch-identify a JSON array of {ip, port, banner}
//	GET  /health       liveness probe
//
// The handler is hardened against oversized bodies, record floods, and panics;
// it never fails the whole batch because of an unrecognizable banner.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"banner-fingerprint/internal/fingerprint"
	"banner-fingerprint/internal/jsonx"
)

const (
	defaultMaxBodyBytes = 8 << 20 // 8 MiB
	defaultMaxRecords   = 10000
	defaultMaxConcurrent = 64
)

// Config configures the HTTP server.
type Config struct {
	Addr          string
	Version       string
	Engine        *fingerprint.Engine
	Logger        *slog.Logger
	MaxBodyBytes  int64
	MaxRecords    int
	MaxConcurrent int
}

// Server wraps an engine plus request guards.
type Server struct {
	cfg     Config
	logger  *slog.Logger
	version string
	sem     chan struct{}
}

// New builds a Server, applying defaults for unset limits.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = defaultMaxBodyBytes
	}
	if cfg.MaxRecords <= 0 {
		cfg.MaxRecords = defaultMaxRecords
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = defaultMaxConcurrent
	}
	return &Server{
		cfg:     cfg,
		logger:  cfg.Logger,
		version: cfg.Version,
		sem:     make(chan struct{}, cfg.MaxConcurrent),
	}
}

// Handler returns the wrapped HTTP handler (routing + middleware).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /fingerprint", s.handleFingerprint)
	return s.recoverMiddleware(s.logMiddleware(mux))
}

// HTTPServer returns a fully time-boxed http.Server for this handler.
func (s *Server) HTTPServer() *http.Server {
	return &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.version})
}

func (s *Server) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	// Bound concurrent fingerprint requests to keep CPU/memory predictable.
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		writeError(w, http.StatusServiceUnavailable, "too many concurrent requests")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var records []fingerprint.Record
	if err := jsonx.Decode(body, &records); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if len(records) == 0 {
		writeJSON(w, http.StatusOK, []fingerprint.Result{})
		return
	}
	if len(records) > s.cfg.MaxRecords {
		writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("too many records: %d (max %d)", len(records), s.cfg.MaxRecords))
		return
	}

	writeJSON(w, http.StatusOK, s.cfg.Engine.IdentifyBatch(records))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(sw, r)
		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"status", sw.status,
			"dur", time.Since(start).String(),
		)
	})
}

func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("panic recovered", "panic", rec, "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
