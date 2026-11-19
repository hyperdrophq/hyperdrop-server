package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Machine describes the computer the rig ran on.
type Machine struct {
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	CPU         string `json:"cpu,omitempty"`
	Cores       int    `json:"cores"`
	MemoryBytes int64  `json:"memoryBytes,omitempty"`
	FileSystem  string `json:"fileSystem,omitempty"`
}

// ServerInfo names the server that was measured. Commit is what the
// server's binary says it was built from, empty when it says nothing.
type ServerInfo struct {
	Version string `json:"version,omitempty"`
	Commit  string `json:"commit,omitempty"`
	BaseURL string `json:"baseURL,omitempty"`
	Local   bool   `json:"local"`
}

// VolumeInfo describes the data volume the scenarios ran against.
type VolumeInfo struct {
	Shares   int64          `json:"shares"`
	Files    int64          `json:"files"`
	Accounts int            `json:"accounts"`
	Seed     int64          `json:"seed"`
	ByKind   map[string]int `json:"byKind,omitempty"`
	Dir      string         `json:"dir,omitempty"`
}

// Run is one complete rig run. Scale is the run's --scale, zero in a run
// saved without it; Only is the scenario names it asked for, empty for all.
type Run struct {
	At        time.Time  `json:"at"`
	Machine   Machine    `json:"machine"`
	Server    ServerInfo `json:"server"`
	Volume    VolumeInfo `json:"volume"`
	Scale     float64    `json:"scale,omitempty"`
	Only      []string   `json:"only,omitempty"`
	Scenarios []Scenario `json:"scenarios"`
}

// ThisMachine fills what it can cheaply; dir is where the data volume lives.
func ThisMachine(dir string) Machine {
	m := Machine{OS: runtime.GOOS, Arch: runtime.GOARCH, Cores: runtime.NumCPU()}
	m.CPU, m.MemoryBytes = cpuAndMemory()
	m.FileSystem = fileSystemOf(dir)
	return m
}

// Save writes the run as indented JSON to <dir>/run-<UTC timestamp>.json,
// through SaveAs, and answers the path.
func Save(r Run, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	at := r.At
	if at.IsZero() {
		at = time.Now()
	}
	path := filepath.Join(dir, "run-"+at.UTC().Format("20060102T150405.000Z")+".json")
	return path, SaveAs(r, path)
}

// SaveAs writes the run as indented JSON to path, replacing what is there
// whole: it writes a temporary file beside path and renames it over path, so
// a run saved again after every scenario is never left half written.
func SaveAs(r Run, path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(append(data, '\n'))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o644)
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// Load reads a run saved by Save.
func Load(path string) (Run, error) {
	var r Run
	data, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return r, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

func atoi(s string) int64 { n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64); return n }
