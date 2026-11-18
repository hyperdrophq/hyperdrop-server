package releasemanifest

import (
	"strconv"
	"testing"
)

// The server manifest is fetched from the website. One that parses has a
// newest release, a readable version no other release is newer than, and
// versions order the same way from either side.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"releases":[{"version":"1.8.1","date":"2026-11-17","linux":{"amd64":{"length":3,"sha256":"ab"}}},{"version":"1.7.10"}]}`))
	f.Add([]byte(`{"serverPending":"1.9.0","releases":[{"version":"01.2.3"},{"version":"1.2"},{"version":"1.2.3"}]}`))
	f.Add([]byte(`{"releases":[{"version":"99999999999999999999.0.0"}]}`))
	f.Add([]byte(`{"releases":[]}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Parse(data)
		if err != nil {
			if len(m.Releases) != 0 || m.ServerPending != "" {
				t.Fatalf("a refused manifest answered %+v", m)
			}
			return
		}
		newest, ok := m.Newest()
		if !ok || !Valid(newest.Version) {
			t.Fatalf("a parsed manifest's newest is %q, %v", newest.Version, ok)
		}
		for _, r := range m.Releases {
			if Less(newest.Version, r.Version) {
				t.Fatalf("%q is newer than the newest, %q", r.Version, newest.Version)
			}
			if Less(r.Version, r.Version) || (Less(r.Version, newest.Version) && Less(newest.Version, r.Version)) {
				t.Fatalf("%q and %q order both ways", r.Version, newest.Version)
			}
			c, ok := Contract(r.Version)
			if ok != Valid(r.Version) {
				t.Fatalf("Contract(%q) = %q, %v; Valid = %v", r.Version, c, ok, Valid(r.Version))
			}
			if p, vok := parse(r.Version); vok {
				if want := strconv.Itoa(p[0]) + "." + strconv.Itoa(p[1]) + "." + strconv.Itoa(p[2]); want != r.Version {
					t.Fatalf("%q reads as %s", r.Version, want)
				}
			}
		}
	})
}
