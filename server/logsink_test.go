package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// On a NAS the server's stderr is a file nothing rotates while it runs, so
// the serving log goes to the rotating file alone; elsewhere stderr (the
// journal) gets every line too.
func TestTheSynologyChannelLogsOnlyToTheRotatingFile(t *testing.T) {
	var logs bytes.Buffer
	if w := logSink("synology", &logs); w != &logs {
		t.Fatalf("synology sink = %T, want the rotating file itself", w)
	}
	if w := logSink("", &logs); w == &logs {
		t.Fatal("a systemd box logs to the rotating file alone, so the journal shows nothing")
	}
}

func TestCertMagicLogsThroughTheSink(t *testing.T) {
	var logs bytes.Buffer
	certLogger(&logs).Info("certificate obtained successfully")
	if !strings.Contains(logs.String(), "certificate obtained successfully") {
		t.Fatalf("sink got %q", logs.String())
	}
}

// CertMagic's lines carry the same timestamp as the server's own (UTC,
// "2006/01/02 15:04:05"), so one log reads in one format.
func TestCertificateLinesUseTheServersTimestamp(t *testing.T) {
	var buf bytes.Buffer
	certLogger(&buf).Info("maintenance", zap.String("cache", "x"))
	line := buf.String()
	if !regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} INFO maintenance`).MatchString(line) {
		t.Fatalf("certificate line %q does not start with the server's timestamp", line)
	}
}
