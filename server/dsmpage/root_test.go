package dsmpage

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeRoot is a rootStep whose every system call is recorded, standing in
// for a DSM 6 CGI process that starts as root.
type fakeRoot struct {
	calls   []string
	euids   []int // answered in turn; the last one repeats
	exeUID  int
	exeMode os.FileMode
	dirUID  int
	dirMode os.FileMode
	user    string
	authErr error
	lookupE error
	setuidE error
}

func (f *fakeRoot) step() rootStep {
	return rootStep{
		Euid: func() int {
			e := f.euids[0]
			if len(f.euids) > 1 {
				f.euids = f.euids[1:]
			}
			return e
		},
		Exe: func() (string, error) { return "/volume1/@appstore/hyperdrop/bin/hyperdrop-server", nil },
		Stat: func(path string) (int, os.FileMode, error) {
			if strings.HasSuffix(path, "/bin") {
				f.calls = append(f.calls, "stat-dir")
				return f.dirUID, f.dirMode, nil
			}
			f.calls = append(f.calls, "stat-exe")
			return f.exeUID, f.exeMode, nil
		},
		Lookup: func(name string) (int, int, error) {
			f.calls = append(f.calls, "lookup "+name)
			return 257575, 257575, f.lookupE
		},
		Setgroups: func(g []int) error { f.calls = append(f.calls, "setgroups"); return nil },
		Setgid:    func(g int) error { f.calls = append(f.calls, "setgid"); return nil },
		Setuid:    func(u int) error { f.calls = append(f.calls, "setuid"); return f.setuidE },
		Authenticate: func(ctx context.Context, env []string) (string, error) {
			f.calls = append(f.calls, "authenticate")
			return f.user, f.authErr
		},
	}
}

func safeRoot() *fakeRoot {
	return &fakeRoot{euids: []int{0, 257575}, exeUID: 0, exeMode: 0o755, dirUID: 0, dirMode: 0o755 | os.ModeDir, user: "alice"}
}

func sentinelDeps() (*Deps, *int) {
	n := 0
	return &Deps{Authenticate: func(context.Context, []string) (string, error) { n++; return "sentinel", nil }}, &n
}

func TestRootStepDoesNothingWhenNotRoot(t *testing.T) {
	f := safeRoot()
	f.euids = []int{1000}
	d, n := sentinelDeps()
	if err := f.step().run(context.Background(), cgiEnv, d); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 {
		t.Errorf("calls as a non-root process: %v", f.calls)
	}
	d.Authenticate(context.Background(), nil)
	if *n != 1 {
		t.Error("Authenticate was replaced in a non-root process")
	}
}

func TestRootStepRefusesAProgramThePackageUserCanWrite(t *testing.T) {
	for _, c := range []struct {
		name             string
		exeUID, dirUID   int
		exeMode, dirMode os.FileMode
	}{
		{"the program is the package user's", 257575, 0, 0o755, 0o755 | os.ModeDir},
		{"the program is group-writable", 0, 0, 0o775, 0o755 | os.ModeDir},
		{"its directory is world-writable", 0, 0, 0o755, 0o777 | os.ModeDir},
		{"its directory is the package user's", 0, 257575, 0o755, 0o755 | os.ModeDir},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := safeRoot()
			f.exeUID, f.dirUID, f.exeMode, f.dirMode = c.exeUID, c.dirUID, c.exeMode, c.dirMode
			d, _ := sentinelDeps()
			err := f.step().run(context.Background(), cgiEnv, d)
			if !errors.Is(err, errUnsafeInstall) {
				t.Fatalf("err = %v, want errUnsafeInstall", err)
			}
			for _, call := range f.calls {
				if call == "setuid" || call == "authenticate" {
					t.Errorf("%s ran on an unsafe install: %v", call, f.calls)
				}
			}
		})
	}
}

func TestRootStepAuthenticatesThenDrops(t *testing.T) {
	f := safeRoot()
	d, n := sentinelDeps()
	if err := f.step().run(context.Background(), cgiEnv, d); err != nil {
		t.Fatal(err)
	}
	want := []string{"stat-exe", "stat-dir", "authenticate", "lookup hyperdrop", "setgroups", "setgid", "setuid"}
	if !slices.Equal(f.calls, want) {
		t.Errorf("calls = %v, want %v", f.calls, want)
	}
	before := len(f.calls)
	user, err := d.Authenticate(context.Background(), nil)
	if err != nil || user != "alice" {
		t.Errorf("memoised Authenticate = %q, %v; want alice", user, err)
	}
	if len(f.calls) != before || *n != 0 {
		t.Error("the memoised answer ran a program")
	}
}

func TestRootStepSkipsAuthenticateWithoutTheToken(t *testing.T) {
	f := safeRoot()
	d, _ := sentinelDeps()
	env := []string{"HTTP_COOKIE=id=session", "REMOTE_ADDR=192.0.2.7", "HTTP_X_SYNO_TOKEN="}
	if err := f.step().run(context.Background(), env, d); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.calls, "authenticate") {
		t.Errorf("authenticate ran without the token header: %v", f.calls)
	}
	if !slices.Contains(f.calls, "setuid") {
		t.Errorf("the drop did not happen: %v", f.calls)
	}
	if user, _ := d.Authenticate(context.Background(), nil); user != "" {
		t.Errorf("memoised user = %q, want none", user)
	}
}

func TestRootStepRefusesWhenTheDropDoesNotTake(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(*fakeRoot)
	}{
		{"euid stays 0", func(f *fakeRoot) { f.euids = []int{0} }},
		{"the package user is unknown", func(f *fakeRoot) { f.lookupE = errors.New("unknown user") }},
		{"setuid fails", func(f *fakeRoot) { f.setuidE = errors.New("EPERM") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := safeRoot()
			c.set(f)
			d, _ := sentinelDeps()
			if err := f.step().run(context.Background(), cgiEnv, d); !errors.Is(err, errCannotDrop) {
				t.Fatalf("err = %v, want errCannotDrop", err)
			}
		})
	}
}

func TestServeAnswers500WhenTheRootStepFails(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	w := httptest.NewRecorder()
	serveRefusal(errUnsafeInstall).ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"`+errUnsafeInstall.Error()+`"`) {
		t.Errorf("body %s", w.Body)
	}
}

// The one program root runs is bounded like the package user's run of it.
func TestRootStepBoundsAuthenticate(t *testing.T) {
	f := safeRoot()
	var left time.Duration
	step := f.step()
	inner := step.Authenticate
	step.Authenticate = func(ctx context.Context, env []string) (string, error) {
		if dl, ok := ctx.Deadline(); ok {
			left = time.Until(dl)
		}
		return inner(ctx, env)
	}
	d, _ := sentinelDeps()
	if err := step.run(context.Background(), cgiEnv, d); err != nil {
		t.Fatal(err)
	}
	if left <= 0 || left > commandTimeout {
		t.Errorf("authenticate ran with %v left, want a deadline within %v", left, commandTimeout)
	}
}
