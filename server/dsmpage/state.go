package dsmpage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// docsBase is where each message's help link points; the anchors are
// written on the Synology docs page.
const docsBase = "https://gethyperdrop.com/docs/synology/#"

const (
	logMaxBytes = 256 << 10
	logMaxLines = 200
)

// Address is the server's address: Kind "free" (Value the name before
// .hyperdrop.link) or "domain" (Value the domain), or "" when the conf holds
// neither.
type Address struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// Action is the one thing a message offers: Fill puts Fill into the proxy
// field, URL opens URL.
type Action struct {
	Label string `json:"label"`
	Fill  string `json:"fill,omitempty"`
	URL   string `json:"url,omitempty"`
}

// Message is one sentence about the server's state, its help link and,
// sometimes, an action.
type Message struct {
	Code   string  `json:"code"`
	Text   string  `json:"text"`
	Link   string  `json:"link"`
	Action *Action `json:"action,omitempty"`
}

// State is what the Settings tab shows.
type State struct {
	Running   bool      `json:"running"`
	Version   string    `json:"version"`
	Address   Address   `json:"address"`
	HTTPPort  int       `json:"httpPort"`
	HTTPSPort int       `json:"httpsPort"`
	Proxy     string    `json:"proxy"`
	Messages  []Message `json:"messages"`
	Log       string    `json:"log"`
	// PendingAddress is an address change waiting in address-request; nil
	// when none waits.
	PendingAddress *Address `json:"pendingAddress,omitempty"`
	// LastChange is the last Save's progress or outcome; nil before any.
	LastChange *ChangeReport `json:"lastChange,omitempty"`
}

// statusFile is the part of the server's status file this page reads
// (server/statusfile.go Status).
type statusFile struct {
	Version      string `json:"version"`
	LastError    string `json:"lastError"`
	ProxySources []struct {
		Addr string `json:"addr"`
		Kind string `json:"kind"`
	} `json:"proxySources"`
	PublicProxy    int   `json:"publicProxyHeaders"`
	MissingFiles   int   `json:"missingFiles"`
	Reachable      *bool `json:"reachable"`
	AddressPending *struct {
		Address     string `json:"address"`
		Reason      string `json:"reason"`
		ApprovalURL string `json:"approvalURL"`
	} `json:"addressPending"`
}

func (p *page) serveState(w http.ResponseWriter, r *http.Request, user string) {
	writeJSON(w, http.StatusOK, p.readState())
}

func (p *page) readState() State {
	conf := readConf(p.deps.ConfPath)
	var st statusFile
	if b, err := readCapped(p.deps.StatusPath); err == nil {
		json.Unmarshal(b, &st)
	}
	s := State{
		Running:   p.running(),
		Version:   st.Version,
		HTTPPort:  portOf(conf["HTTP_ADDR"]),
		HTTPSPort: portOf(conf["HTTPS_ADDR"]),
		Proxy:     conf["TRUSTED_PROXIES"],
	}
	switch {
	case conf["DDNS_NAME"] != "":
		s.Address = Address{"free", conf["DDNS_NAME"]}
	case conf["DOMAIN"] != "":
		s.Address = Address{"domain", conf["DOMAIN"]}
	}
	s.Messages = messagesFor(st, s)
	s.Log = p.readLog(conf["SHARED_FOLDER"])
	s.PendingAddress = p.pendingAddress(conf)
	s.LastChange = p.lastChange()
	return s
}

// messagesFor words the status file for the page. A stopped server's file
// still holds the last run's counts, so only its last problem is shown.
func messagesFor(st statusFile, s State) []Message {
	out := []Message{}
	add := func(code, text, anchor string, a *Action) {
		out = append(out, Message{Code: code, Text: text, Link: docsBase + anchor, Action: a})
	}
	if st.LastError != "" {
		add("last-error", "Last problem: "+st.LastError, "settings-page", nil)
	}
	if s.HTTPPort > 0 && s.HTTPSPort > 0 && (s.HTTPPort != 5080 || s.HTTPSPort != 5443) {
		add("firewall-ports", fmt.Sprintf("If DSM's firewall is on, allow ports %d and %d for HyperDrop.", s.HTTPPort, s.HTTPSPort), "firewall", nil)
	}
	if !s.Running {
		return out
	}
	if pe := st.AddressPending; pe != nil && pe.Address != "" {
		var a *Action
		if approvalURLOK(pe.ApprovalURL) {
			a = &Action{Label: "Approve " + pe.Address, URL: pe.ApprovalURL}
		}
		add("address-pending", "Waiting to switch to "+pe.Address+": "+pe.Reason, "settings-page", a)
	}
	for _, src := range st.ProxySources {
		switch src.Kind {
		case "untrusted-header":
			add("proxy-untrusted", fmt.Sprintf("Connections from %s start with a PROXY header, but %s is not set as a proxy address, so every secure connection fails. Set %s as the proxy address below.",
				src.Addr, src.Addr, src.Addr), "proxy-header", &Action{Label: "Use " + src.Addr, Fill: src.Addr})
		case "trusted-no-header":
			add("proxy-no-header", src.Addr+" is set as the proxy address but sends no PROXY header, so its connections fail. Turn on send-proxy-v2 in the proxy, or clear the proxy address.", "proxy-header", nil)
		}
	}
	if st.PublicProxy > 0 {
		add("proxy-public", "Connections from the internet start with a PROXY header. A proxy in front of HyperDrop must be on this network.", "proxy-header", nil)
	}
	if st.MissingFiles > 0 {
		add("files-missing", missingFilesText(st.MissingFiles), "missing-files", nil)
	}
	if st.Reachable != nil && !*st.Reachable && s.HTTPSPort > 0 {
		port := strconv.Itoa(s.HTTPSPort)
		add("not-reachable", "Running on port "+port+", not reachable from the internet yet. Check that your router forwards port 443 to "+port+".", "ports", nil)
	}
	return out
}

// missingFilesText is the server's own health text for missing files
// (server/internal/api/health.go).
func missingFilesText(n int) string {
	if n == 1 {
		return "1 file is missing from HyperDrop's data folder. Restore it from a backup of the folder."
	}
	return fmt.Sprintf("%d files are missing from HyperDrop's data folder. Restore them from a backup of the folder.", n)
}

// running is true when some process executes the server binary, the check
// the package's start-stop-status makes: the DSM page's CGI and its Save
// worker run the same binary and are not the server.
func (p *page) running() bool {
	target := p.deps.ServerBinary
	if t, err := filepath.EvalSymlinks(target); err == nil {
		target = t
	}
	entries, err := os.ReadDir(p.deps.ProcRoot)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if n := e.Name(); n == "" || n[0] < '0' || n[0] > '9' {
			continue
		}
		exe, err := os.Readlink(filepath.Join(p.deps.ProcRoot, e.Name(), "exe"))
		if err != nil {
			continue
		}
		if strings.TrimSuffix(exe, " (deleted)") == target && !notServer(filepath.Join(p.deps.ProcRoot, e.Name(), "cmdline")) {
			return true
		}
	}
	return false
}

// notServer is true unless the command line at path (NUL-separated) is a
// server's: the start script runs the server with no argument, while the
// DSM page, its Save worker and the operator subcommands run the same binary
// with one, and a command line that cannot be read or is empty belongs to a
// process that has exited, since a live server's always holds its program
// name.
func notServer(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, 4096))
	if len(b) == 0 {
		return true
	}
	return strings.Contains(strings.TrimSuffix(string(b), "\x00"), "\x00")
}

// dataDir resolves the data folder the conf's shared folder name names, as
// start-stop-status does: DSM's link to it under SharesDir, followed. ok is
// false when the name is not one folder's or the link does not resolve, as
// for a locked or missing folder.
func (p *page) dataDir(folder string) (dir string, ok bool) {
	if folder == "" || folder == "." || folder == ".." || strings.ContainsAny(folder, "/\x00") {
		return "", false
	}
	dir, err := filepath.EvalSymlinks(filepath.Join(p.deps.SharesDir, folder))
	if err != nil {
		return "", false
	}
	return dir, true
}

// readLog answers the tail of the server log in the data folder the conf
// names: its last logMaxLines lines within the last logMaxBytes bytes.
func (p *page) readLog(folder string) string {
	dir, ok := p.dataDir(folder)
	if !ok {
		return ""
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return ""
	}
	defer root.Close()
	f, err := root.Open("logs/server.log")
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	cut := false
	if fi.Size() > logMaxBytes {
		if _, err := f.Seek(-logMaxBytes, io.SeekEnd); err != nil {
			return ""
		}
		cut = true
	}
	b, err := io.ReadAll(io.LimitReader(f, logMaxBytes))
	if err != nil {
		return ""
	}
	if cut {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	text := strings.TrimSuffix(string(b), "\n")
	if n := strings.Count(text, "\n") + 1; n > logMaxLines {
		for i := 0; i < n-logMaxLines; i++ {
			text = text[strings.IndexByte(text, '\n')+1:]
		}
	}
	if text == "" {
		return ""
	}
	return text + "\n"
}

const confMaxBytes = 1 << 20

// readCapped reads at most confMaxBytes of a file.
func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, confMaxBytes))
}

// approvalURLOK is true for the link the names service builds for an
// address approval: https, on gethyperdrop.com or a subdomain, no userinfo,
// under /account/.
func approvalURLOK(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || !strings.HasPrefix(u.Path, "/account/") {
		return false
	}
	h := u.Hostname()
	return h == "gethyperdrop.com" || strings.HasSuffix(h, ".gethyperdrop.com")
}

// readConf reads the conf's HYPERDROP_KEY=value lines as text, keyed by KEY, unquoting a double-quoted
// value; the first line of a key wins. It never runs the file.
func readConf(path string) map[string]string {
	b, err := readCapped(path)
	if err != nil {
		return map[string]string{}
	}
	return parseConf(b)
}

// parseConf is readConf on the conf's bytes.
func parseConf(b []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), "=")
		k = strings.TrimPrefix(k, "HYPERDROP_")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		if _, seen := out[k]; seen {
			continue
		}
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out
}

// portOf answers the port of a listen address like ":5443", or 0.
func portOf(addr string) int {
	n, err := strconv.Atoi(addr[strings.LastIndex(addr, ":")+1:])
	if err != nil || n < 1 || n > 65535 {
		return 0
	}
	return n
}
