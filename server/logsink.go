package main

import (
	"io"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// logSink is where the serving process's log lines go: its own rotating file
// (data/logs/server.log), and stderr beside it, which a systemd unit sends to
// the journal. A Synology package sends stderr to a plain file that only a
// package start rotates, so on that channel the rotating file is the only
// destination, and stderr carries only what the Go runtime writes there
// itself, a panic's trace.
func logSink(channel string, logs io.Writer) io.Writer {
	if channel == "synology" {
		return logs
	}
	return io.MultiWriter(os.Stderr, logs)
}

// certLogger is CertMagic's logger over the same sink, so certificate and
// ACME events land in server.log beside everything else; its own default
// writes to stderr alone. Its lines start like the server's own: the UTC
// time as "2006/01/02 15:04:05", then the level and the message, fields
// separated by single spaces.
func certLogger(w io.Writer) *zap.Logger {
	cfg := zap.NewProductionEncoderConfig()
	cfg.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.UTC().Format("2006/01/02 15:04:05"))
	}
	cfg.EncodeLevel = zapcore.CapitalLevelEncoder
	cfg.ConsoleSeparator = " "
	return zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(cfg),
		zapcore.AddSync(w),
		zap.InfoLevel,
	))
}
