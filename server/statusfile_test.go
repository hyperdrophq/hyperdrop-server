package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
)

func TestReachableFollowsTheAddressKind(t *testing.T) {
	free := "box." + ddns.Zone
	own := "files.example.com"
	b := func(v bool) *bool { return &v }
	cases := []struct {
		name        string
		host        string
		https, http string
		notProbed   bool
		want        *bool
	}{
		{"free both ok", free, "ok", "ok", false, b(true)},
		{"free http closed", free, "ok", "closed", false, b(false)},
		{"free http taken", free, "ok", "taken", false, b(false)},
		{"free http unknown", free, "ok", "unknown", false, nil},
		{"free https closed", free, "closed", "ok", false, b(false)},
		{"free https taken", free, "taken", "ok", false, b(false)},
		{"free https unknown", free, "unknown", "ok", false, nil},
		{"free not probed", free, "ok", "ok", true, nil},
		{"own https ok http closed", own, "ok", "closed", false, b(true)},
		{"own https ok http unknown", own, "ok", "unknown", false, b(true)},
		{"own https ok http taken", own, "ok", "taken", false, b(true)},
		{"own https closed", own, "closed", "ok", false, b(false)},
		{"own https taken", own, "taken", "ok", false, b(false)},
		{"own https unknown", own, "unknown", "ok", false, nil},
		{"own not probed", own, "ok", "ok", true, nil},
	}
	for _, c := range cases {
		got := reachableFrom(c.host, domain.Ports{HTTPS: c.https, HTTP: c.http}, !c.notProbed)
		if (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func readStatus(t *testing.T, path string) Status {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var s Status
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStatusWriterWritesOnlyWhenTheJSONChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	w := newStatusWriter(path)
	w.Update(func(s *Status) { s.Version = "1.0.0"; s.MissingFiles = 2 })
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	w.Update(func(s *Status) { s.Version = "1.0.0"; s.MissingFiles = 2 })
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.ModTime().After(old.Add(time.Minute)) {
		t.Fatalf("an unchanged status was rewritten: mtime %v", fi.ModTime())
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
	w.Update(func(s *Status) { s.MissingFiles = 3 })
	if got := readStatus(t, path).MissingFiles; got != 3 {
		t.Fatalf("missingFiles = %d, want 3", got)
	}
	if fi2, _ := os.Stat(path); !fi2.ModTime().After(old.Add(time.Minute)) {
		t.Fatal("a changed status was not written")
	}
}

func TestNilStatusWriterIsANoOp(t *testing.T) {
	var w *statusWriter
	w.Update(func(s *Status) { s.Version = "x" })
	w.Set(Status{Version: "x"})
	if newStatusWriter("") != nil {
		t.Fatal("an empty path must give a nil writer")
	}
}

func TestStatusWriterSetReplacesAnEarlierRefusal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	if err := os.WriteFile(path, []byte(`{"lastError":"old","at":5}`), 0o600); err != nil {
		t.Fatal(err)
	}
	w := newStatusWriter(path)
	w.Set(Status{Version: "1.0.0", StartedAt: 9})
	got := readStatus(t, path)
	if got.LastError != "" || got.At != 0 || got.Version != "1.0.0" || got.StartedAt != 9 {
		t.Fatalf("status = %+v", got)
	}
}

func TestBindFailureRecordsThePortInUse(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	port := strconv.Itoa(held.Addr().(*net.TCPAddr).Port)
	path := filepath.Join(t.TempDir(), "status.json")
	w := newStatusWriter(path)
	if _, err := listenRecording(w, held.Addr().String()); err == nil {
		t.Fatal("binding a held port succeeded")
	}
	got := readStatus(t, path)
	want := "Port " + port + " is already in use by another app."
	if got.LastError != want || got.At == 0 {
		t.Fatalf("status = %+v, want lastError %q", got, want)
	}
}

func TestBindFailureOtherErrorNamesThePort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	w := newStatusWriter(path)
	if _, err := listenRecording(w, "256.0.0.1:5443"); err == nil {
		t.Fatal("binding a bad address succeeded")
	}
	got := readStatus(t, path).LastError
	if !strings.HasPrefix(got, "HyperDrop could not open port 5443: ") || !strings.HasSuffix(got, ".") {
		t.Fatalf("lastError = %q", got)
	}
}
