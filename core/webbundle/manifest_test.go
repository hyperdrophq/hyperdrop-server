package webbundle

import "testing"

func rel(version string, build int, contract string) Release {
	return Release{Version: version, Build: build, Contract: contract}
}

func TestPickPrefersSameMinor(t *testing.T) {
	m := Manifest{Releases: []Release{rel("1.3.0", 1, "1.3.0"), rel("1.2.0", 1, "1.2.0"), rel("1.1.0", 1, "1.1.0")}}
	got, ok := Pick(m, "1.2.5")
	if !ok || got.Contract != "1.2.0" {
		t.Fatalf("got %+v %v", got, ok)
	}
}

func TestPickNewestByVersionThenBuild(t *testing.T) {
	m := Manifest{Releases: []Release{
		rel("1.9.0", 2, "1.2.0"), rel("1.10.0", 1, "1.2.0"), rel("1.10.0", 3, "1.2.0"), rel("1.10.0", 2, "1.2.0"),
	}}
	got, ok := Pick(m, "1.2.0")
	if !ok || got.Version != "1.10.0" || got.Build != 3 {
		t.Fatalf("got %+v %v", got, ok)
	}
}

func TestPickFallsBackOneMinorBelow(t *testing.T) {
	m := Manifest{Releases: []Release{rel("1.1.0", 1, "1.1.0"), rel("1.1.1", 1, "1.1.0")}}
	got, ok := Pick(m, "1.2.0")
	if !ok || got.Version != "1.1.1" {
		t.Fatalf("got %+v %v", got, ok)
	}
}

func TestPickNeverNewerMinor(t *testing.T) {
	if _, ok := Pick(Manifest{Releases: []Release{rel("1.3.0", 1, "1.3.0")}}, "1.2.0"); ok {
		t.Fatal("picked a newer minor")
	}
	if _, ok := Pick(Manifest{Releases: []Release{rel("1.0.0", 1, "1.0.0")}}, "1.2.0"); ok {
		t.Fatal("picked two minors below")
	}
	if _, ok := Pick(Manifest{Releases: []Release{rel("1.1.0", 1, "1.1.0")}}, "2.2.0"); ok {
		t.Fatal("picked across a major")
	}
	if _, ok := Pick(Manifest{}, "1.2.0"); ok {
		t.Fatal("picked from nothing")
	}
}

func TestServes(t *testing.T) {
	for _, c := range []struct {
		bundle, server string
		want           bool
	}{
		{"1.2.0", "1.2.5", true},
		{"1.1.0", "1.2.0", true},
		{"1.3.0", "1.2.0", false},
		{"1.0.0", "1.2.0", false},
		{"2.1.0", "1.2.0", false},
		{"1.2.0", "2.2.0", false},
		{"1.0.0", "2.0.0", false},
		{"junk", "1.2.0", false},
		{"1.2.0", "junk", false},
	} {
		if got := Serves(c.bundle, c.server); got != c.want {
			t.Errorf("Serves(%s, %s) = %v", c.bundle, c.server, got)
		}
	}
}

func TestManifestStrict(t *testing.T) {
	good := `{"releases":[{"version":"1.0.0","build":1,"date":"2026-10-25","contract":"1.2.0","sha256":"x","size":3,"url":"u","sig":"s"}]}`
	m, err := ParseManifest([]byte(good))
	if err != nil || len(m.Releases) != 1 || m.Releases[0].Size != 3 {
		t.Fatalf("%+v %v", m, err)
	}
	for _, bad := range []string{
		`{"releases":[],"extra":1}`,
		`{"releases":[{"version":"1.0.0","bogus":1}]}`,
		`{"releases":[]} {}`,
		`{"releases":[]}}`,
		`nope`,
	} {
		if _, err := ParseManifest([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		av    string
		ab    int
		bv    string
		bb    int
		newer bool
	}{
		{"1.10.0", 1, "1.9.9", 9, true},
		{"1.0.1", 1, "1.0.1", 2, false},
		{"1.0.1", 3, "1.0.1", 2, true},
		{"1.0.1", 2, "1.0.1", 2, false},
		{"2.0.0", 1, "1.99.0", 50, true},
		{"1.0.0", 9, "1.0.1", 1, false},
	} {
		if got := Newer(c.av, c.ab, c.bv, c.bb); got != c.newer {
			t.Errorf("Newer(%s build %d, %s build %d) = %v, want %v", c.av, c.ab, c.bv, c.bb, got, c.newer)
		}
	}
}
