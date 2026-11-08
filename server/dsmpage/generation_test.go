package dsmpage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadMajor(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, c := range []struct {
		name string
		file string
		want int
	}{
		{"DSM 6", write("six", "majorversion=\"6\"\nminorversion=\"2\"\nproductversion=\"6.2.3\"\n"), 6},
		{"DSM 7", write("seven", "majorversion=\"7\"\nminorversion=\"2\"\n"), 7},
		{"no file", filepath.Join(dir, "missing"), 7},
		{"not a number", write("odd", "majorversion=\"x\"\n"), 7},
	} {
		if got := readMajor(c.file); got != c.want {
			t.Errorf("%s: readMajor = %d, want %d", c.name, got, c.want)
		}
	}
}

// targetLink makes a target link the way DSM keeps it: a link under the
// package directory to the program tree on a volume.
func targetLink(t *testing.T, root, volume string) string {
	t.Helper()
	tree := filepath.Join(root, volume, "@appstore", "hyperdrop")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "packages", "hyperdrop", "target")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(tree, link); err != nil {
		t.Fatal(err)
	}
	return link
}

func TestDSM6VarDirFollowsTheTargetLink(t *testing.T) {
	root := t.TempDir()
	link := targetLink(t, root, "volume2")
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := dsm6VarDir(link), filepath.Join(resolved, "volume2", "@appdata", "hyperdrop"); got != want {
		t.Errorf("dsm6VarDir = %q, want %q", got, want)
	}
}

func TestDSM6VarDirNeedsAVolume(t *testing.T) {
	root := t.TempDir()
	if got := dsm6VarDir(targetLink(t, root, "nowhere")); got != "" {
		t.Errorf("a target under no volume gave %q", got)
	}
	dangling := filepath.Join(root, "dangling")
	if err := os.Symlink(filepath.Join(root, "gone"), dangling); err != nil {
		t.Fatal(err)
	}
	if got := dsm6VarDir(dangling); got != "" {
		t.Errorf("a dangling target gave %q", got)
	}
}

func dsm6Deps(target string) Deps {
	return Deps{
		Major:        6,
		Target:       target,
		Environ:      func() []string { return cgiEnv },
		Authenticate: func(context.Context, []string) (string, error) { return "alice", nil },
		Groups:       func(context.Context, string) ([]string, error) { return []string{"administrators"}, nil },
		ProcRoot:     "/nonexistent",
	}
}

func TestNewPageOnDSM6DerivesThePaths(t *testing.T) {
	root := t.TempDir()
	p := newPage(dsm6Deps(targetLink(t, root, "volume1")))
	resolved, _ := filepath.EvalSymlinks(root)
	want := filepath.Join(resolved, "volume1", "@appdata", "hyperdrop")
	if p.deps.VarDir != want {
		t.Errorf("VarDir = %q, want %q", p.deps.VarDir, want)
	}
	if p.deps.ConfPath != want+"/hyperdrop.conf" || p.deps.StatusPath != want+"/status.json" {
		t.Errorf("conf %q, status %q are not under the var directory", p.deps.ConfPath, p.deps.StatusPath)
	}
}

func TestNewPageOnDSM6WithoutAVolumeStillAnswers(t *testing.T) {
	root := t.TempDir()
	p := newPage(dsm6Deps(targetLink(t, root, "nowhere")))
	if p.deps.VarDir != "" || p.deps.ConfPath != "" {
		t.Fatalf("VarDir %q, ConfPath %q: a target under no volume must leave them empty", p.deps.VarDir, p.deps.ConfPath)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.Header.Set("X-SYNO-TOKEN", "tok")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("state: %d %s", w.Code, w.Body)
	}
	if st := decodeMap(t, w); st["running"] != false {
		t.Errorf("running = %v", st["running"])
	}
}

// A DSM 6 whose target names no volume has nowhere to write: a Save or a
// rescue is refused with the sentence, and nothing lands in the CGI's
// working directory under a relative name.
func TestNewPageOnDSM6WithoutAVolumeRefusesWrites(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	root := t.TempDir()
	p := newPage(dsm6Deps(targetLink(t, root, "nowhere")))
	for _, c := range []struct{ path, body string }{
		{"/api/settings", `{"kind":"free","address":"alice","httpPort":5080,"httpsPort":5443}`},
		{"/api/rescue", `{"account":"admin","password":"a new password"}`},
	} {
		req := httptest.NewRequest(http.MethodPost, c.path, strings.NewReader(c.body))
		req.Header.Set("X-SYNO-TOKEN", "tok")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), dsm6MissingText) {
			t.Errorf("POST %s: %d %s", c.path, w.Code, w.Body)
		}
	}
	entries, _ := os.ReadDir(cwd)
	if len(entries) != 0 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("files written under relative names: %v", names)
	}
}
