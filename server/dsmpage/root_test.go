package dsmpage

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
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
	rootUID int // the package root, above bin
	rootMod os.FileMode
	exeErr  error
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
		Exe: func() (string, error) { return "/volume1/@appstore/hyperdrop/bin/hyperdrop-server", f.exeErr },
		Stat: func(path string) (int, os.FileMode, error) {
			if strings.HasSuffix(path, "/bin") {
				f.calls = append(f.calls, "stat-dir")
				return f.dirUID, f.dirMode, nil
			}
			if strings.HasSuffix(path, "/@appstore/hyperdrop") {
				f.calls = append(f.calls, "stat-root")
				return f.rootUID, f.rootMod, nil
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
	}
}

func safeRoot() *fakeRoot {
	return &fakeRoot{euids: []int{0, 257575}, exeUID: 0, exeMode: 0o755, dirUID: 0, dirMode: 0o755 | os.ModeDir, rootUID: 0, rootMod: 0o755 | os.ModeDir}
}

func TestRootStepDoesNothingWhenNotRoot(t *testing.T) {
	f := safeRoot()
	f.euids = []int{1000}
	if err := f.step().run(); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 {
		t.Errorf("calls as a non-root process: %v", f.calls)
	}
}

func TestRootStepRefusesAProgramThePackageUserCanWrite(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(*fakeRoot)
	}{
		{"the program is the package user's", func(f *fakeRoot) { f.exeUID = 257575 }},
		{"the program is group-writable", func(f *fakeRoot) { f.exeMode = 0o775 }},
		{"its directory is world-writable", func(f *fakeRoot) { f.dirMode = 0o777 | os.ModeDir }},
		{"its directory is the package user's", func(f *fakeRoot) { f.dirUID = 257575 }},
		{"the package root is the package user's", func(f *fakeRoot) { f.rootUID = 257575 }},
		{"the package root is group-writable", func(f *fakeRoot) { f.rootMod = 0o775 | os.ModeDir }},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := safeRoot()
			c.set(f)
			err := f.step().run()
			if !errors.Is(err, errUnsafeInstall) {
				t.Fatalf("err = %v, want errUnsafeInstall", err)
			}
			if !slices.Contains(f.calls, "setuid") {
				t.Errorf("the refusal is served as root: no drop in %v", f.calls)
			}
		})
	}
}

// A process that cannot name its own program says so, and still stops
// being root before it answers.
func TestRootStepNamesAMissingProgram(t *testing.T) {
	f := safeRoot()
	f.exeErr = errors.New("readlink /proc/self/exe: no such file")
	if err := f.step().run(); !errors.Is(err, errNoProgram) {
		t.Fatalf("err = %v, want errNoProgram", err)
	}
	if !slices.Contains(f.calls, "setuid") {
		t.Errorf("calls = %v: want a drop", f.calls)
	}
}

// As root the step only stats and drops: no program runs and nothing of
// the request is read before the process is the package user.
func TestRootStepOnlyStatsThenDrops(t *testing.T) {
	f := safeRoot()
	if err := f.step().run(); err != nil {
		t.Fatal(err)
	}
	want := []string{"stat-exe", "stat-dir", "stat-root", "lookup hyperdrop", "setgroups", "setgid", "setuid"}
	if !slices.Equal(f.calls, want) {
		t.Errorf("calls = %v, want %v", f.calls, want)
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
			if err := f.step().run(); !errors.Is(err, errCannotDrop) {
				t.Fatalf("err = %v, want errCannotDrop", err)
			}
		})
	}
}
