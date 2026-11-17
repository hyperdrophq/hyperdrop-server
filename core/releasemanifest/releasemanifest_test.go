package releasemanifest

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

const manifest = `{"serverPending":"1.3.0","releases":[
 {"version":"1.2.0","date":"2026-11-20"},
 {"version":"1.1.1","date":"2026-11-05","linux":{"amd64":{"length":3,"sha256":"aa"}}},
 {"version":"../x","date":"2026-12-01"},
 {"version":"1.1.0","date":"2026-11-01","notes":["n"],"builds":["dsm7-x86_64"],"minServerManagementBuild":2},
 {"version":"1.0.1","date":"2026-10-01"}]}`

func day(s string) time.Time { d, _ := time.Parse("2006-01-02", s); return d }

func TestParseReadsEveryField(t *testing.T) {
	m, err := Parse([]byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	if m.ServerPending != "1.3.0" || len(m.Releases) != 5 {
		t.Fatalf("%+v", m)
	}
	r := m.Releases[3]
	if r.Version != "1.1.0" || r.MinServerManagementBuild != 2 || r.Notes[0] != "n" || r.Builds[0] != "dsm7-x86_64" {
		t.Fatalf("%+v", r)
	}
	if m.Releases[1].Linux["amd64"].Length != 3 {
		t.Fatalf("%+v", m.Releases[1])
	}
	if d, ok := r.Published(); !ok || !d.Equal(day("2026-11-01")) {
		t.Fatalf("published %v %v", d, ok)
	}
}

func TestParseRefusesGarbageAndAListWithoutAReadableVersion(t *testing.T) {
	for _, b := range []string{`nope`, `{"releases":[]}`, `{"releases":[{"version":"v1"}]}`} {
		if _, err := Parse([]byte(b)); err == nil {
			t.Errorf("%s parsed", b)
		}
	}
}

func TestNewestIgnoresOrderAndUnreadableVersions(t *testing.T) {
	m, _ := Parse([]byte(`{"releases":[{"version":"1.9.0"},{"version":"1.10.0"},{"version":"2.0.0-rc1"}]}`))
	if r, ok := m.Newest(); !ok || r.Version != "1.10.0" {
		t.Fatalf("newest %q %v", r.Version, ok)
	}
}

func TestLessAndContractAreNumeric(t *testing.T) {
	if !Less("1.9.0", "1.10.0") || Less("1.10.0", "1.9.0") || Less("1.0.1", "1.0.1") {
		t.Fatal("Less")
	}
	if !Less("junk", "0.0.1") || Less("0.0.1", "junk") {
		t.Fatal("an unreadable version sorts first")
	}
	if c, ok := Contract("1.10.3"); !ok || c != "1.10" {
		t.Fatalf("contract %q", c)
	}
	if _, ok := Contract("1.10"); ok {
		t.Fatal("a contract is read from MAJOR.MINOR.PATCH only")
	}
	if Valid("01.a.3") || Valid("1.2") || !Valid("1.2.3") {
		t.Fatal("Valid")
	}
}

func TestCheckDigest(t *testing.T) {
	gz := []byte("gzip bytes")
	sum := sha256.Sum256(gz)
	f := File{Length: int64(len(gz)), SHA256: hex.EncodeToString(sum[:])}
	if err := CheckDigest("x.gz", gz, f); err != nil {
		t.Fatal(err)
	}
	if err := CheckDigest("x.gz", append(gz, '!'), f); err == nil || !strings.Contains(err.Error(), "x.gz does not match the published size and checksum") {
		t.Fatalf("err = %v", err)
	}
	if BinaryName("1.1.0", "arm64") != "hyperdrop-server-1.1.0-linux-arm64.gz" {
		t.Fatal(BinaryName("1.1.0", "arm64"))
	}
}
