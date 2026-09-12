// Command server runs the banner fingerprint HTTP service.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"banner-fingerprint/internal/fingerprint"
	"banner-fingerprint/internal/server"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel()}))
	slog.SetDefault(logger)

	engine := loadEngine(logger)
	addr := listenAddr()

	srv := server.New(server.Config{
		Addr:            addr,
		Version:         version,
		Engine:          engine,
		Logger:          logger,
		MaxBodyBytes:    envInt64("MAX_BODY_BYTES", 8<<20),
		MaxRecords:      envInt("MAX_RECORDS", 10000),
		MaxConcurrent:   envInt("MAX_CONCURRENT", 64),
		RateLimitPerSec: envFloat("RATE_LIMIT_PER_SEC", 20),
		RateLimitBurst:  envInt("RATE_LIMIT_BURST", 40),
	})
	httpSrv := srv.HTTPServer()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("fingerprint server starting", "addr", addr, "version", version)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("shutdown signal received, draining")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		_ = httpSrv.Close()
	}
	logger.Info("server stopped")
}

func loadEngine(logger *slog.Logger) *fingerprint.Engine {
	path, err := fingerprint.ResolveRulesPath(rulesCandidates())
	if err != nil {
		logger.Error("no rules file found", "err", err)
		os.Exit(1)
	}
	rules, err := fingerprint.LoadRulesFile(path)
	if err != nil {
		logger.Error("load rules failed", "err", err)
		os.Exit(1)
	}
	engine, err := fingerprint.NewEngine(rules)
	if err != nil {
		logger.Error("build engine failed", "err", err)
		os.Exit(1)
	}
	logger.Info("rules loaded", "path", path, "count", len(rules))
	return engine
}

func rulesCandidates() []string {
	if p := os.Getenv("RULES_PATH"); p != "" {
		return []string{p}
	}
	return []string{"rules/rules.json", "./rules/rules.json", "../rules/rules.json", "/rules/rules.json"}
}

func listenAddr() string {
	if p := os.Getenv("PORT"); p != "" {
		return ":" + p
	}
	return ":8080"
}

func logLevel() slog.Level {
	switch os.Getenv("LOG_LEVEL") {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func envInt64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// envFloat parses a floating-point setting such as the per-second rate limit.
// Fractional rates are useful for exposing a small budget (a rate of 0.5 means
// one request every two seconds). Values that are absent, malformed, or
// non-positive fall back to def.
func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			return f
		}
	}
	return def
}
