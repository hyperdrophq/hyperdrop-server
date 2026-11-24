package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"hyperdrop/server/internal/loadrig/report"
	"hyperdrop/server/internal/loadrig/scenario"
	"hyperdrop/server/internal/loadrig/target"
	"hyperdrop/server/internal/metadb"
)

func TestMain(m *testing.M) {
	metadb.BcryptCost = bcrypt.MinCost
	os.Exit(m.Run())
}

func exec(t *testing.T, args ...string) (code int, out, errOut string) {
	t.Helper()
	var o, e bytes.Buffer
	code = run(args, &o, &e)
	return code, o.String(), e.String()
}

func TestGenerateRunAndCompareEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a server")
	}
	vol := filepath.Join(t.TempDir(), "vol")
	if code, out, errOut := exec(t, "generate", "--dir", vol, "--shares", "300"); code != 0 {
		t.Fatalf("generate exit %d\n%s\n%s", code, out, errOut)
	} else if !strings.Contains(out, "Estimated disk use") || !strings.Contains(out, "Generated 300 shares") {
		t.Fatalf("generate output lacks the plan or the totals:\n%s", out)
	}
	results := filepath.Join(t.TempDir(), "results")
	code, out, errOut := exec(t, "run", "--dir", vol, "--only", "reads", "--scale", "0.05", "--out", results)
	if code != 0 {
		t.Fatalf("run exit %d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "== reads ==") || !strings.Contains(out, "Saved ") {
		t.Fatalf("run output lacks the table or the saved path:\n%s", out)
	}
	if !strings.Contains(out, "== volume ==") || !strings.Contains(out, "database file at end") {
		t.Fatalf("run output lacks the volume's sizes:\n%s", out)
	}
	saved, _ := filepath.Glob(filepath.Join(results, "run-*.json"))
	if len(saved) != 1 {
		t.Fatalf("saved results = %v", saved)
	}
	got, err := report.Load(saved[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Scenarios) != 2 || got.Scenarios[0].Name != scenario.VolumeName || got.Scenarios[1].Name != "reads" ||
		got.Scale != 0.05 || strings.Join(got.Only, ",") != "reads" {
		t.Fatalf("saved run: scale %v, only %v, scenarios %+v", got.Scale, got.Only, got.Scenarios)
	}
	code, out, errOut = exec(t, "compare", saved[0], saved[0])
	if code != 0 || !strings.Contains(out, "reads") {
		t.Fatalf("compare exit %d\n%s\n%s", code, out, errOut)
	}
}

func TestGenerateRefusesADirectoryHoldingAForeignFile(t *testing.T) {
	dir := t.TempDir()
	foreign := filepath.Join(dir, "mine.txt")
	if err := os.WriteFile(foreign, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := exec(t, "generate", "--dir", dir, "--shares", "300"); code == 0 {
		t.Fatalf("generate into a foreign directory exited 0; stderr %q", errOut)
	}
	if b, err := os.ReadFile(foreign); err != nil || string(b) != "keep" {
		t.Fatalf("the foreign file changed: %q, %v", b, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("generate left %d entries in the directory", len(entries))
	}
}

func TestRunNamesTheValidScenariosForAnUnknownOne(t *testing.T) {
	code, _, errOut := exec(t, "run", "--dir", t.TempDir(), "--only", "reads,nope")
	if code == 0 {
		t.Fatal("an unknown scenario exited 0")
	}
	for _, name := range []string{"nope", "housekeeping", "reads", "overload"} {
		if !strings.Contains(errOut, name) {
			t.Fatalf("stderr does not name %q:\n%s", name, errOut)
		}
	}
}

func TestSourcesPrintsTheAliasHint(t *testing.T) {
	code, out, _ := exec(t, "sources", "--add", "4")
	if code != 0 || !strings.Contains(out, "127.0.0.1") {
		t.Fatalf("sources exit %d\n%s", code, out)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"bogus"}, {"run"}, {"generate", "--dir", "x"}, {"compare", "one.json"}} {
		if code, _, _ := exec(t, args...); code == 0 {
			t.Fatalf("%v exited 0", args)
		}
	}
}

func TestProjectNeedsGeneratedVolumes(t *testing.T) {
	if code, _, _ := exec(t, "project", "--small", t.TempDir(), "--large", t.TempDir(), "--shares", "1000"); code == 0 {
		t.Fatal("project over directories that are not volumes exited 0")
	}
}

func TestWaitBootingSaysItIsWaitingUntilTheStartReturns(t *testing.T) {
	var buf bytes.Buffer
	tg, err := waitBooting(&buf, 10*time.Millisecond, func() (target.Target, error) {
		time.Sleep(55 * time.Millisecond)
		return target.Remote("http://127.0.0.1:1"), nil
	})
	if err != nil || tg == nil {
		t.Fatalf("waitBooting = %v, %v", tg, err)
	}
	lines := strings.Count(buf.String(), "waiting for the server to boot: ")
	if lines < 3 {
		t.Fatalf("%d waiting lines over 55 ms at a 10 ms pace:\n%s", lines, buf.String())
	}
	time.Sleep(30 * time.Millisecond)
	if after := strings.Count(buf.String(), "waiting for the server to boot: "); after != lines {
		t.Fatalf("waitBooting printed %d lines after the start returned", after-lines)
	}
}
