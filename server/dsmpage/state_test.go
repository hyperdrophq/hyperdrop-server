package dsmpage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// stateRig is a package directory tree in a temp dir: var/ (conf, status),
// shares/<folder> (the data folder, reached through a link) and a fake /proc.
type stateRig struct {
	t    *testing.T
	root string
	deps Deps
}

const rigBin = "/var/packages/hyperdrop/target/bin/hyperdrop-server"

func newStateRig(t *testing.T, conf string) *stateRig {
	t.Helper()
	root := t.TempDir()
	r := &stateRig{t: t, root: root}
	for _, d := range []string{"var", "shares", "proc", "real/logs"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "shares", "hyperdrop")); err != nil {
		t.Fatal(err)
	}
	r.deps = Deps{
		Environ:      func() []string { return cgiEnv },
		Authenticate: func(_ context.Context, _ []string) (string, error) { return "alice", nil },
		Groups:       func(_ context.Context, _ string) ([]string, error) { return []string{"administrators"}, nil },
		ConfPath:     filepath.Join(root, "var", "hyperdrop.conf"),
		StatusPath:   filepath.Join(root, "var", "status.json"),
		SharesDir:    filepath.Join(root, "shares"),
		ProcRoot:     filepath.Join(root, "proc"),
		ServerBinary: rigBin,
		VarDir:       filepath.Join(root, "var"),
	}
	r.write("var/hyperdrop.conf", conf)
	return r
}

func (r *stateRig) write(rel, text string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.root, rel), []byte(text), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func (r *stateRig) status(text string) { r.write("var/status.json", text) }

func (r *stateRig) run(exe string) {
	r.t.Helper()
	dir := filepath.Join(r.root, "proc", "4242")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		r.t.Fatal(err)
	}
	link := filepath.Join(dir, "exe")
	os.Remove(link)
	if err := os.Symlink(exe, link); err != nil {
		r.t.Fatal(err)
	}
	r.write("proc/4242/cmdline", strings.TrimSuffix(exe, " (deleted)")+"\x00")
}

func (r *stateRig) get() State {
	r.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.Header.Set("X-SYNO-TOKEN", "tok")
	w := httptest.NewRecorder()
	New(r.deps).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		r.t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var s State
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		r.t.Fatal(err)
	}
	return s
}

const freeConf = "HYPERDROP_DOMAIN=\nHYPERDROP_DDNS_NAME=alice\nHYPERDROP_HTTP_ADDR=:5080\n" +
	"HYPERDROP_HTTPS_ADDR=:5443\nHYPERDROP_TRUSTED_PROXIES=\"\"\nHYPERDROP_SHARED_FOLDER=\"hyperdrop\"\n"

func (s State) message(code string) *Message {
	for i := range s.Messages {
		if s.Messages[i].Code == code {
			return &s.Messages[i]
		}
	}
	return nil
}

func TestStateReadsTheConf(t *testing.T) {
	r := newStateRig(t, freeConf)
	r.status(`{"version":"1.2.3"}`)
	r.run(rigBin)
	s := r.get()
	if !s.Running || s.Version != "1.2.3" {
		t.Fatalf("running/version: %+v", s)
	}
	if s.Address.Kind != "free" || s.Address.Value != "alice" || s.HTTPPort != 5080 || s.HTTPSPort != 5443 || s.Proxy != "" {
		t.Fatalf("conf fields: %+v", s)
	}
	if len(s.Messages) != 0 {
		t.Fatalf("a healthy server shows no messages: %+v", s.Messages)
	}
}

func TestStateOwnDomainAndProxy(t *testing.T) {
	r := newStateRig(t, "HYPERDROP_DOMAIN=share.example.com\nHYPERDROP_DDNS_NAME=\nHYPERDROP_HTTP_ADDR=:8080\n"+
		"HYPERDROP_HTTPS_ADDR=:8443\nHYPERDROP_TRUSTED_PROXIES=\"10.0.0.1 10.0.0.2/32\"\nHYPERDROP_SHARED_FOLDER=\"hyperdrop\"\n")
	s := r.get()
	if s.Address.Kind != "domain" || s.Address.Value != "share.example.com" || s.HTTPSPort != 8443 || s.Proxy != "10.0.0.1 10.0.0.2/32" {
		t.Fatalf("%+v", s)
	}
}

func TestStateRunningChecksTheBinary(t *testing.T) {
	r := newStateRig(t, freeConf)
	r.run("/usr/bin/other")
	if r.get().Running {
		t.Fatal("another program is not the server")
	}
	r.run(rigBin + " (deleted)")
	if !r.get().Running {
		t.Fatal("a replaced binary still running is the server")
	}
}

func TestStateAbsentFilesAreStopped(t *testing.T) {
	r := newStateRig(t, freeConf)
	r.deps.ConfPath = filepath.Join(r.root, "var", "absent.conf")
	r.deps.StatusPath = filepath.Join(r.root, "var", "absent.json")
	s := r.get()
	if s.Running || len(s.Messages) != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestStateStoppedShowsLastError(t *testing.T) {
	r := newStateRig(t, freeConf)
	r.status(`{"lastError":"Port 5443 is already in use by another app.","at":1,"reachable":false}`)
	s := r.get()
	if s.Running {
		t.Fatal("nothing runs")
	}
	m := s.message("last-error")
	if m == nil || m.Text != "Last problem: Port 5443 is already in use by another app." || !strings.HasSuffix(m.Link, "#settings-page") {
		t.Fatalf("%+v", s.Messages)
	}
	if len(s.Messages) != 1 {
		t.Fatalf("a stopped server shows only its last problem: %+v", s.Messages)
	}
}

func TestStateUntrustedHeaderSource(t *testing.T) {
	r := newStateRig(t, freeConf)
	r.run(rigBin)
	r.status(`{"proxySources":[{"addr":"192.168.1.31","count":4,"lastSeen":1,"kind":"untrusted-header"}]}`)
	m := r.get().message("proxy-untrusted")
	want := "Connections from 192.168.1.31 start with a PROXY header, but 192.168.1.31 is not set as a proxy address, so every secure connection fails. Set 192.168.1.31 as the proxy address below."
	if m == nil || m.Text != want || !strings.HasSuffix(m.Link, "#proxy-header") {
		t.Fatalf("%+v", m)
	}
	if m.Action == nil || m.Action.Label != "Use 192.168.1.31" || m.Action.Fill != "192.168.1.31" {
		t.Fatalf("the one-tap fill: %+v", m.Action)
	}
}

func TestStateTrustedNoHeaderSource(t *testing.T) {
	r := newStateRig(t, freeConf)
	r.run(rigBin)
	r.status(`{"proxySources":[{"addr":"10.0.0.1","count":2,"lastSeen":1,"kind":"trusted-no-header"}]}`)
	m := r.get().message("proxy-no-header")
	want := "10.0.0.1 is set as the proxy address but sends no PROXY header, so its connections fail. Turn on send-proxy-v2 in the proxy, or clear the proxy address."
	if m == nil || m.Text != want || !strings.HasSuffix(m.Link, "#proxy-header") || m.Action != nil {
		t.Fatalf("%+v", m)
	}
}

func TestStatePublicProxyHeaders(t *testing.T) {
	r := newStateRig(t, freeConf)
	r.run(rigBin)
	r.status(`{"publicProxyHeaders":3}`)
	m := r.get().message("proxy-public")
	want := "Connections from the internet start with a PROXY header. A proxy in front of HyperDrop must be on this network."
	if m == nil || m.Text != want || !strings.HasSuffix(m.Link, "#proxy-header") {
		t.Fatalf("%+v", m)
	}
}

func TestStateMissingFiles(t *testing.T) {
	r := newStateRig(t, freeConf)
	r.run(rigBin)
	r.status(`{"missingFiles":1}`)
	m := r.get().message("files-missing")
	if m == nil || m.Text != "1 file is missing from HyperDrop's data folder. Restore it from a backup of the folder." || !strings.HasSuffix(m.Link, "#missing-files") {
		t.Fatalf("%+v", m)
	}
	r.status(`{"missingFiles":5}`)
	if m := r.get().message("files-missing"); m == nil || m.Text != "5 files are missing from HyperDrop's data folder. Restore them from a backup of the folder." {
		t.Fatalf("%+v", m)
	}
}

// The texts are the server's own, written in internal/api/health.go.
func TestMissingFilesTextsMatchTheServers(t *testing.T) {
	src, err := os.ReadFile("../internal/api/health.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		"1 file is missing from HyperDrop's data folder. Restore it from a backup of the folder.",
		"%d files are missing from HyperDrop's data folder. Restore them from a backup of the folder.",
	} {
		if !strings.Contains(string(src), s) {
			t.Errorf("health.go does not hold %q", s)
		}
	}
}

func TestStateNotReachable(t *testing.T) {
	r := newStateRig(t, freeConf)
	r.run(rigBin)
	r.status(`{"reachable":false}`)
	m := r.get().message("not-reachable")
	want := "Running on port 5443, not reachable from the internet yet. Check that your router forwards port 443 to 5443."
	if m == nil || m.Text != want || !strings.HasSuffix(m.Link, "#ports") {
		t.Fatalf("%+v", m)
	}
	r.status(`{"reachable":true}`)
	if r.get().message("not-reachable") != nil {
		t.Fatal("reachable shows nothing")
	}
}

func TestStateAddressPending(t *testing.T) {
	r := newStateRig(t, freeConf)
	r.run(rigBin)
	r.status(`{"addressPending":{"address":"bob.hyperdrop.link","reason":"waiting for you to approve it","approvalURL":"https://alice.gethyperdrop.com/account/#code=x"}}`)
	m := r.get().message("address-pending")
	if m == nil || m.Text != "Waiting to switch to bob.hyperdrop.link: waiting for you to approve it" || !strings.HasSuffix(m.Link, "#settings-page") {
		t.Fatalf("%+v", m)
	}
	if m.Action == nil || m.Action.Label != "Approve bob.hyperdrop.link" || m.Action.URL != "https://alice.gethyperdrop.com/account/#code=x" {
		t.Fatalf("%+v", m.Action)
	}
	r.status(`{"addressPending":{"address":"bob.hyperdrop.link","reason":"r"}}`)
	if m := r.get().message("address-pending"); m == nil || m.Action != nil {
		t.Fatalf("no approval link, no action: %+v", m)
	}
}

func TestStateLogTail(t *testing.T) {
	r := newStateRig(t, freeConf)
	var b strings.Builder
	for i := 1; i <= 300; i++ {
		b.WriteString("line " + strconv.Itoa(i) + "\n")
	}
	r.write("real/logs/server.log", b.String())
	lines := strings.Split(strings.TrimRight(r.get().Log, "\n"), "\n")
	if len(lines) != 200 || lines[0] != "line 101" || lines[199] != "line 300" {
		t.Fatalf("%d lines, %q..%q", len(lines), lines[0], lines[len(lines)-1])
	}
}

func TestStateLogIsBounded(t *testing.T) {
	r := newStateRig(t, freeConf)
	r.write("real/logs/server.log", "HEAD-MARKER"+strings.Repeat("x", 4<<20)+"\nend\n")
	log := r.get().Log
	if len(log) > 256<<10 || strings.Contains(log, "HEAD-MARKER") || !strings.HasSuffix(log, "end\n") {
		t.Fatalf("%d bytes", len(log))
	}
}

func TestStateApprovalURLIsChecked(t *testing.T) {
	for url, ok := range map[string]bool{
		"https://alice.gethyperdrop.com/account/#code=x": true,
		"https://gethyperdrop.com/account/#code=x":       true,
		"javascript:alert(1)":                            false,
		"http://alice.gethyperdrop.com/account/#code=x":  false,
		"https://evil.example.com/account/#code=x":       false,
		"https://notgethyperdrop.com/account/#code=x":    false,
		"https://x@alice.gethyperdrop.com/account/":      false,
		"https://alice.gethyperdrop.com/other/":          false,
		"":                                               false,
	} {
		r := newStateRig(t, freeConf)
		r.run(rigBin)
		b, _ := json.Marshal(map[string]any{"addressPending": map[string]string{"address": "bob.hyperdrop.link", "reason": "r", "approvalURL": url}})
		r.status(string(b))
		m := r.get().message("address-pending")
		if m == nil {
			t.Fatalf("%q: the waiting message stays", url)
		}
		if (m.Action != nil) != ok {
			t.Errorf("%q: action %+v, want action %v", url, m.Action, ok)
		}
	}
}

func TestStateLogSymlinksAreNotFollowed(t *testing.T) {
	r := newStateRig(t, freeConf)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "server.log"), []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logs := filepath.Join(r.root, "real", "logs")
	if err := os.Remove(logs); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, logs); err != nil {
		t.Fatal(err)
	}
	if got := r.get().Log; got != "" {
		t.Fatalf("a linked logs folder was read: %q", got)
	}
	if err := os.Remove(logs); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "server.log"), filepath.Join(logs, "server.log")); err != nil {
		t.Fatal(err)
	}
	if got := r.get().Log; got != "" {
		t.Fatalf("a linked server.log was read: %q", got)
	}
}

func TestStateUnknownHTTPSPortHasNoReachabilityMessage(t *testing.T) {
	r := newStateRig(t, "HYPERDROP_DDNS_NAME=alice\n")
	r.run(rigBin)
	r.status(`{"reachable":false}`)
	if m := r.get().message("not-reachable"); m != nil {
		t.Fatalf("%+v", m)
	}
}

func TestStateNoLogIsEmpty(t *testing.T) {
	r := newStateRig(t, freeConf)
	if r.get().Log != "" {
		t.Fatal("no log, no text")
	}
}

func TestStateNeedsAnAdmin(t *testing.T) {
	r := newStateRig(t, freeConf)
	r.deps.Groups = func(_ context.Context, _ string) ([]string, error) { return nil, nil }
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.Header.Set("X-SYNO-TOKEN", "tok")
	w := httptest.NewRecorder()
	New(r.deps).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("%d", w.Code)
	}
}

func TestStateAsksToOpenNonDefaultPortsInTheFirewall(t *testing.T) {
	custom := strings.Replace(strings.Replace(freeConf, ":5080", ":8080", 1), ":5443", ":8443", 1)
	r := newStateRig(t, custom)
	r.run(rigBin)
	m := r.get().message("firewall-ports")
	if m == nil {
		t.Fatal("custom ports owe a firewall message")
	}
	if m.Text != "If DSM's firewall is on, allow ports 8080 and 8443 for HyperDrop." || m.Link != docsBase+"firewall" {
		t.Fatalf("%+v", m)
	}
	// The ports come from the conf, so a stopped server shows the message too.
	st := newStateRig(t, custom)
	if st.get().message("firewall-ports") == nil {
		t.Fatal("a stopped server with custom ports owes the firewall message")
	}
	d := newStateRig(t, freeConf)
	d.run(rigBin)
	if d.get().message("firewall-ports") != nil {
		t.Fatal("the default ports owe no firewall message")
	}
}
