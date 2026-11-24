package webbundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Release is one web bundle in the manifest.
type Release struct {
	Version  string `json:"version"`
	Build    int    `json:"build"`
	Date     string `json:"date"`
	Contract string `json:"contract"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	URL      string `json:"url"`
	Sig      string `json:"sig"`
}

// Manifest is the web release manifest.
type Manifest struct {
	Releases []Release `json:"releases"`
}

// ParseManifest reads a manifest strictly: an unknown field or trailing data
// is an error.
func ParseManifest(data []byte) (Manifest, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("web manifest: %w", err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("web manifest: trailing data")
	}
	return m, nil
}

// Serves reports whether a bundle speaking bundleContract works with a server
// of serverContract: the same MAJOR.MINOR, or the same MAJOR and a MINOR one
// below the server's. A bundle for a newer minor is never served: it may call
// routes the server lacks.
func Serves(bundleContract, serverContract string) bool {
	b, ok := dotted(bundleContract)
	if !ok {
		return false
	}
	s, ok := dotted(serverContract)
	if !ok {
		return false
	}
	return b[0] == s[0] && (b[1] == s[1] || b[1] == s[1]-1)
}

// newer reports whether a is a later release than b: version, then build.
func newer(a, b Release) bool {
	return Newer(a.Version, a.Build, b.Version, b.Build)
}

// Newer reports whether version aVersion build aBuild is a later release
// than bVersion build bBuild: version, then build. A version that does not
// parse reads as 0.0.0.
func Newer(aVersion string, aBuild int, bVersion string, bBuild int) bool {
	av, _ := dotted(aVersion)
	bv, _ := dotted(bVersion)
	for i := range av {
		if av[i] != bv[i] {
			return av[i] > bv[i]
		}
	}
	return aBuild > bBuild
}

// Pick chooses the bundle a server of serverContract installs among the
// releases Serves admits: the newest whose contract has the server's
// MAJOR.MINOR, else the newest one minor below it. A release whose version or
// contract does not parse is skipped.
func Pick(m Manifest, serverContract string) (Release, bool) {
	s, ok := dotted(serverContract)
	if !ok {
		return Release{}, false
	}
	var best [2]*Release // [0] same minor, [1] one minor below
	for i := range m.Releases {
		r := &m.Releases[i]
		if _, ok := dotted(r.Version); !ok || !Serves(r.Contract, serverContract) {
			continue
		}
		c, _ := dotted(r.Contract)
		slot := 1
		if c[1] == s[1] {
			slot = 0
		}
		if best[slot] == nil || newer(*r, *best[slot]) {
			best[slot] = r
		}
	}
	for _, r := range best {
		if r != nil {
			return *r, true
		}
	}
	return Release{}, false
}
