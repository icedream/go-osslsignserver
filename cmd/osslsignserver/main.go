package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/icedream/go-osslsignserver/internal/config"
	"github.com/icedream/go-osslsignserver/pkg/bootstrap"
)

func main() {
	// Configure structured logging to stderr.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	// 1. Load configuration
	cfg, err := config.LoadConfig("config.yml")
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	level, err := parseLogLevel(cfg.LogLevel)
	if err != nil {
		slog.Error("Failed to parse log level", "error", err)
		os.Exit(1)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})))

	// 2. Initialize all application components
	appConfig, err := bootstrap.Initialize(cfg)
	if err != nil {
		slog.Error("Failed to initialize application", "error", err)
		os.Exit(1)
	}

	// 3. Start HTTP server
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{
		Port: 6973,
	})
	if err != nil {
		slog.Error("Failed to start listener", "error", err)
		os.Exit(1)
	}

	slog.Info("Starting OSSLSignServer", "port", 6973)
	if err := appConfig.Router.RunListener(listener); err != nil {
		slog.Error("Failed to run server", "error", err)
		os.Exit(1)
	}
}

func parseLogLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log level %q", value)
	}
}
