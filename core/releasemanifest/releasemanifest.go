// Package releasemanifest reads the website's server manifest
// (website/downloads/server/releases.json): which releases exist, when each
// was published, and the facts a download is checked against. Pure: no I/O and no clock, so the
// server's self-updater and every client read the file the same way
// (server/pureimports_test.go lists it).
package releasemanifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// DefaultBase is where the website publishes the manifest (releases.json)
// and the binaries.
const DefaultBase = "https://gethyperdrop.com/downloads/server/"

// File is one published binary's size and SHA-256, over the gzip file.
type File struct {
	Length int64  `json:"length"`
	SHA256 string `json:"sha256"`
}

// Release is one entry of the manifest.
type Release struct {
	Version                  string          `json:"version"`
	Date                     string          `json:"date,omitempty"`
	MinServerManagementBuild int             `json:"minServerManagementBuild,omitempty"`
	Notes                    []string        `json:"notes,omitempty"`
	Builds                   []string        `json:"builds,omitempty"`
	Linux                    map[string]File `json:"linux,omitempty"`
}

// Manifest is the whole file. ServerPending names a contract whose clients
// are released while its server is not yet (apps first, server last): the
// release scripts and the website checks read it, a server ignores it.
type Manifest struct {
	ServerPending string    `json:"serverPending,omitempty"`
	Releases      []Release `json:"releases"`
}

// Parse reads a manifest. It fails on JSON that does not parse and on a
// manifest with no release whose version reads as MAJOR.MINOR.PATCH.
func Parse(b []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("the server releases are unreadable: %w", err)
	}
	if _, ok := m.Newest(); !ok {
		return Manifest{}, errors.New("the server releases list no readable version")
	}
	return m, nil
}

func parse(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" || (len(p) > 1 && p[0] == '0') {
			return out, false
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// Valid reports whether v reads as MAJOR.MINOR.PATCH.
func Valid(v string) bool { _, ok := parse(v); return ok }

// Less reports whether a is an older release than b. An unreadable version
// sorts before every readable one.
func Less(a, b string) bool {
	pa, oka := parse(a)
	pb, okb := parse(b)
	switch {
	case !oka:
		return okb
	case !okb:
		return false
	}
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

// Contract is a version's MAJOR.MINOR.
func Contract(v string) (string, bool) {
	p, ok := parse(v)
	if !ok {
		return "", false
	}
	return strconv.Itoa(p[0]) + "." + strconv.Itoa(p[1]), true
}

// Published answers the entry's date, UTC midnight.
func (r Release) Published() (time.Time, bool) {
	t, err := time.Parse("2006-01-02", r.Date)
	return t, err == nil
}

// Newest answers the greatest readable version, whatever the entries' order.
func (m Manifest) Newest() (Release, bool) {
	var best Release
	found := false
	for _, r := range m.Releases {
		if !Valid(r.Version) {
			continue
		}
		if !found || Less(best.Version, r.Version) {
			best, found = r, true
		}
	}
	return best, found
}

// BinaryName is the published gzip of a version's Linux build for arch.
func BinaryName(version, arch string) string {
	return "hyperdrop-server-" + version + "-linux-" + arch + ".gz"
}

// CheckDigest refuses a download whose length or SHA-256 is not the one
// the manifest published.
func CheckDigest(name string, gz []byte, f File) error {
	sum := sha256.Sum256(gz)
	if int64(len(gz)) != f.Length || hex.EncodeToString(sum[:]) != f.SHA256 {
		return fmt.Errorf("%s does not match the published size and checksum", name)
	}
	return nil
}
