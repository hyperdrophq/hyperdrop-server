package main

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The server may import only the client core's PURE packages: decisions
// with no I/O, no clock and no platform, so the server and every client
// reach the same verdict from the same code. A core package that dials,
// opens files or runs processes would drag the client's behaviour (its
// registry, its keychain, its network rules) into the server.
var pureCore = map[string]bool{
	"hyperdrop/core/inboxannounce":   true,
	"hyperdrop/core/revokeannounce":  true,
	"hyperdrop/core/domainconn":      true,
	"hyperdrop/core/releasemanifest": true,
	"hyperdrop/core/updatenotice":    true,
	"hyperdrop/core/pushseal":        true,
	"hyperdrop/core/uniquename":      true,
	"hyperdrop/core/sharenamerule":   true,
}

// What a pure package may import beyond other pure core packages. Crypto is
// I/O-free; crypto/rand reads the kernel's generator, which is not a file,
// network or process, so it is allowed too.
var pureStd = map[string]bool{
	"crypto/ecdh": true, "crypto/hpke": true, "crypto/rand": true, "encoding/base64": true,
	"crypto/sha256": true, "encoding/hex": true, "encoding/json": true, "errors": true, "fmt": true,
	"slices": true, "sort": true, "strconv": true, "strings": true, "time": true, "unicode": true,
	"unicode/utf8": true,
}

type goPackage struct {
	ImportPath string
	Imports    []string
	Standard   bool
}

func goList(t *testing.T, args ...string) []goPackage {
	t.Helper()
	// The server's real build: linux, no cgo, so linux-only files are listed.
	cmd := exec.Command("go", append([]string{"list", "-json"}, args...)...)
	cmd.Env = append(os.Environ(), "GOOS=linux", "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %v: %v", args, err)
	}
	var all []goPackage
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for {
		var p goPackage
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		all = append(all, p)
	}
	return all
}

func TestServerImportsOnlyPureCore(t *testing.T) {
	seen := 0
	for _, p := range goList(t, "-deps", "./...") {
		if !strings.HasPrefix(p.ImportPath, "hyperdrop/core") {
			continue
		}
		seen++
		if !pureCore[p.ImportPath] {
			t.Errorf("the server depends on %s, which is not on the pure list", p.ImportPath)
			continue
		}
		for _, imp := range p.Imports {
			if !pureCore[imp] && !pureStd[imp] {
				t.Errorf("%s imports %s: a pure package imports only the standard library's pure packages and other pure core packages", p.ImportPath, imp)
			}
		}
	}
	if seen == 0 {
		t.Fatal("the server imports no core package: the test would pass vacuously")
	}
}
