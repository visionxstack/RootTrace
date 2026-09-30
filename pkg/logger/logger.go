package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Logger wraps slog for structured logging with level control.
type Logger struct {
	handler slog.Handler
	inner   *slog.Logger
}

// Config configures the logger.
type Config struct {
	Level  string // debug, info, warn, error
	Format string // json, text
	Output io.Writer
}

// New creates a new structured logger.
// Logs are always written to stderr (or the configured output) so they
// never contaminate the MCP stdout transport.
func New(cfg Config) *Logger {
	if cfg.Output == nil {
		cfg.Output = os.Stderr
	}

	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if strings.ToLower(cfg.Format) == "text" {
		handler = slog.NewTextHandler(cfg.Output, opts)
	} else {
		handler = slog.NewJSONHandler(cfg.Output, opts)
	}

	return &Logger{
		handler: handler,
		inner:   slog.New(handler),
	}
}

// Default returns a default info-level JSON logger writing to stderr.
func Default() *Logger {
	return New(Config{Level: "info", Format: "json"})
}

func (l *Logger) Debug(msg string, args ...any) { l.inner.Debug(msg, args...) }
func (l *Logger) Info(msg string, args ...any)  { l.inner.Info(msg, args...) }
func (l *Logger) Warn(msg string, args ...any)  { l.inner.Warn(msg, args...) }
func (l *Logger) Error(msg string, args ...any) { l.inner.Error(msg, args...) }

func (l *Logger) With(args ...any) *Logger {
	return &Logger{inner: l.inner.With(args...)}
}

func (l *Logger) WithContext(ctx context.Context) *Logger {
	_ = ctx // future: extract trace ID from context
	return l
}
