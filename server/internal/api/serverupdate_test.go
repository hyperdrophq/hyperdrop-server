package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/updatesig"
)

// updateAPI is a handler whose update route is armed, plus the staging dir the
// installer unit would watch.
func updateAPI(t *testing.T) (http.Handler, string) {
	t.Helper()
	dir := t.TempDir()
	h := newHandler(testBackend(t), "9.9.9", testDomain(t), nil, Deployment{})
	h.dep.UpdateDir = dir
	trusted := updatesig.TrustedKeys
	updatesig.TrustedKeys = []string{base64.StdEncoding.EncodeToString(testReleaseKey.Public().(ed25519.PublicKey))}
	t.Cleanup(func() { updatesig.TrustedKeys = trusted })
	return h.routes(), dir
}

// testReleaseKey stands in for the release key: updateAPI trusts it alone.
var testReleaseKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))

// testSignature is a signature file (core/serversig's format) for body.
func testSignature(key ed25519.PrivateKey, version, arch string, body []byte) []byte {
	sum := sha256.Sum256(body)
	st := "hyperdrop-server-signature 3\nversion " + version + "\narch " + arch +
		"\nsha256 " + hex.EncodeToString(sum[:]) + "\n"
	return []byte(st + "signature " + base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(st))) + "\n")
}

// postUpdate sends body signed by the test release key for this host, as the
// same version the handler runs.
func postUpdate(t *testing.T, h http.Handler, token, password, code string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	return postUpdateSigned(t, h, token, password, code, body,
		testSignature(testReleaseKey, "9.9.9", runtime.GOARCH, body))
}

func postUpdateSigned(t *testing.T, h http.Handler, token, password, code string, body, sig []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/server/update", bytes.NewReader(body))
	if sig != nil {
		req.Header.Set("X-HyperDrop-Signature", base64.StdEncoding.EncodeToString(sig))
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if password != "" {
		req.Header.Set("X-HyperDrop-Password", password)
	}
	if code != "" {
		req.Header.Set("X-HyperDrop-TOTP", code)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func elfBody(size int) []byte {
	b := make([]byte, size)
	copy(b, []byte{0x7f, 'E', 'L', 'F'})
	return b
}

// This route grants ROOT on the box, so it must not rest on a single factor.
// An admin who never set one up is refused with a code that says what to do.
func TestUpdateRefusesAnAdminWithNoSecondFactor(t *testing.T) {
	h, dir := updateAPI(t)
	rec := postUpdate(t, h, testToken, testAdminPassword, "", elfBody(64))
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "totp-setup-required") {
		t.Fatalf("no second factor = %d %s, want 403 totp-setup-required", rec.Code, rec.Body)
	}
	assertNothingStaged(t, dir)
}

// A device token stolen from a Mac's Keychain must not be enough: that is the
// whole reason this is step-up rather than the ordinary admin gate.
func TestUpdateRefusesTheTokenAlone(t *testing.T) {
	h, dir := updateAPI(t)
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	wantStepUpRequired(t, "no password", postUpdate(t, h, testToken, "", nextCode(t, secret), elfBody(64)))
	if rec := postUpdate(t, h, testToken, "wrong-password", nextCode(t, secret), elfBody(64)); rec.Code != 401 {
		t.Fatalf("wrong password = %d, want 401", rec.Code)
	}
	if rec := postUpdate(t, h, testToken, testAdminPassword, "000000", elfBody(64)); rec.Code != 401 {
		t.Fatalf("wrong code = %d, want 401", rec.Code)
	}
	assertNothingStaged(t, dir)
}

func TestUpdateStagesTheBinaryItWasSent(t *testing.T) {
	h, dir := updateAPI(t)
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	body := elfBody(4096)
	body[100] = 0xAB // something to recognise
	rec := postUpdate(t, h, testToken, testAdminPassword, nextCode(t, secret), body)
	if rec.Code != 202 {
		t.Fatalf("update = %d %s, want 202", rec.Code, rec.Body)
	}
	staged, err := os.ReadFile(filepath.Join(dir, stagedName))
	if err != nil {
		t.Fatalf("nothing staged: %v", err)
	}
	if !bytes.Equal(staged, body) {
		t.Fatalf("staged %d bytes, sent %d, and they differ", len(staged), len(body))
	}
	// The .part must be gone: the installer watches for the final name only.
	if _, err := os.Stat(filepath.Join(dir, stagedPartName)); !os.IsNotExist(err) {
		t.Fatal("the partial file survived the rename")
	}
}

// A text file, a macOS build, or a truncated download is refused before
// anything is armed. Not a security boundary (a real attacker sends a valid
// ELF), but it catches the mistake that would otherwise brick the server.
func TestUpdateRefusesSomethingThatIsNotALinuxBinary(t *testing.T) {
	h, dir := updateAPI(t)
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	rec := postUpdate(t, h, testToken, testAdminPassword, nextCode(t, secret),
		[]byte("this is definitely not a server"))
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "not-a-server-binary") {
		t.Fatalf("junk upload = %d %s, want 400 not-a-server-binary", rec.Code, rec.Body)
	}
	assertNothingStaged(t, dir)
}

// The client sends the arch /api/health reported. A mismatch means the wrong
// artifact was chosen, and installing it would leave a server that cannot start.
func TestUpdateRefusesAForeignArchitecture(t *testing.T) {
	h, dir := updateAPI(t)
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	req := httptest.NewRequest("POST", "/api/server/update", bytes.NewReader(elfBody(64)))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-HyperDrop-Password", testAdminPassword)
	req.Header.Set("X-HyperDrop-TOTP", nextCode(t, secret))
	req.Header.Set("X-HyperDrop-Arch", "s390x")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "arch-mismatch") {
		t.Fatalf("foreign arch = %d %s, want 400 arch-mismatch", rec.Code, rec.Body)
	}
	assertNothingStaged(t, dir)
}

// A server installed before the installer unit existed must say so rather than
// accept a binary nothing will ever pick up.
func TestUpdateIsRefusedWhenTheInstallerIsNotPresent(t *testing.T) {
	h := newTestAPI(t) // no updateStagingDir
	rec := postUpdate(t, h, testToken, testAdminPassword, "123456", elfBody(64))
	if rec.Code != 501 || !strings.Contains(rec.Body.String(), "update-unsupported") {
		t.Fatalf("no installer = %d %s, want 501 update-unsupported", rec.Code, rec.Body)
	}
}

func TestANonAdminCannotUpdateTheServer(t *testing.T) {
	_, dir := updateAPI(t)
	// A second handler, because the first seeds only admin.
	b := testBackend(t)
	um := b.DB
	tok := seedUser(t, um, "alice")
	h2 := newHandler(b, "9.9.9", testDomain(t), nil, Deployment{})
	h2.dep.UpdateDir = dir
	if rec := postUpdate(t, h2.routes(), tok, "alice-pw", "123456", elfBody(64)); rec.Code != 403 {
		t.Fatalf("non-admin = %d, want 403", rec.Code)
	}
	assertNothingStaged(t, dir)
}

// /api/health carries what a client needs to pick the right build and to know
// whether this route exists at all.
func TestHealthAdvertisesArchAndUpdateSupport(t *testing.T) {
	h, _ := updateAPI(t)
	rec := doReq(t, h, "GET", "/api/health", "", "")
	body := rec.Body.String()
	if !strings.Contains(body, `"arch"`) {
		t.Fatalf("health does not report arch: %s", body)
	}
	if !strings.Contains(body, `"updateOverAPI":true`) {
		t.Fatalf("health does not advertise update support: %s", body)
	}
	// And a server without the installer says nothing, rather than claiming it.
	rec = doReq(t, newTestAPI(t), "GET", "/api/health", "", "")
	if strings.Contains(rec.Body.String(), "updateOverAPI") {
		t.Fatalf("a server with no installer still advertised updates: %s", rec.Body)
	}
}

func assertNothingStaged(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{stagedName, stagedPartName, stagedSigName} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s exists after a refused update", name)
		}
	}
}

// The installer checks the release signature as root; the route checks it
// first so a refusal reaches the caller, and stages it beside the binary.
func TestUpdateRefusesAnUnsignedOrForeignBinary(t *testing.T) {
	body := elfBody(256)
	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	otherArch := "arm64"
	if runtime.GOARCH == "arm64" {
		otherArch = "amd64"
	}
	for _, c := range []struct {
		name, code string
		sig        []byte
	}{
		{"unsigned", "unsigned-binary", nil},
		{"foreign key", "bad-signature", testSignature(otherKey, "9.9.9", runtime.GOARCH, body)},
		{"other bytes", "bad-signature", testSignature(testReleaseKey, "9.9.9", runtime.GOARCH, elfBody(64))},
		{"other arch", "bad-signature", testSignature(testReleaseKey, "9.9.9", otherArch, body)},
		{"downgrade", "bad-signature", testSignature(testReleaseKey, "9.9.8", runtime.GOARCH, body)},
	} {
		// A fresh server per case: an accepted code is spent, and every case
		// passes the step-up before its signature is judged.
		h, dir := updateAPI(t)
		secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
		rec := postUpdateSigned(t, h, testToken, testAdminPassword, nextCode(t, secret), body, c.sig)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), `"`+c.code+`"`) {
			t.Fatalf("%s: %d %s, want 400 %s", c.name, rec.Code, rec.Body, c.code)
		}
		assertNothingStaged(t, dir)
	}
}

func TestUpdateStagesTheSignatureBesideTheBinary(t *testing.T) {
	h, dir := updateAPI(t)
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	body := elfBody(512)
	if rec := postUpdate(t, h, testToken, testAdminPassword, nextCode(t, secret), body); rec.Code != 202 {
		t.Fatalf("update = %d %s", rec.Code, rec.Body)
	}
	sig, err := os.ReadFile(filepath.Join(dir, stagedSigName))
	if err != nil {
		t.Fatalf("no staged signature: %v", err)
	}
	if !bytes.Equal(sig, testSignature(testReleaseKey, "9.9.9", runtime.GOARCH, body)) {
		t.Fatalf("staged signature = %q", sig)
	}
	// The root installer copies both before it reads them, so nothing but
	// the service account needs to read what is staged.
	for _, name := range []string{stagedName, stagedSigName} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s: %v, %v, want no group or other bits", name, st.Mode().Perm(), err)
		}
	}
}

func TestUpdateBacksUpTheDatabaseBeforeStaging(t *testing.T) {
	dataDir := t.TempDir()
	hd := newHandler(testBackendAt(t, dataDir), "9.9.9", testDomain(t), nil, Deployment{DataDir: dataDir, UpdateDir: t.TempDir()})
	trusted := updatesig.TrustedKeys
	updatesig.TrustedKeys = []string{base64.StdEncoding.EncodeToString(testReleaseKey.Public().(ed25519.PublicKey))}
	t.Cleanup(func() { updatesig.TrustedKeys = trusted })
	h := hd.routes()
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	rec := postUpdate(t, h, testToken, testAdminPassword, nextCode(t, secret), elfBody(4096))
	if rec.Code != 202 {
		t.Fatalf("update = %d %s", rec.Code, rec.Body)
	}
	if metadb.NewestBackup(filepath.Join(dataDir, "backups")) == "" {
		t.Fatal("no backup was written before the update was staged")
	}
}

// A refused upload writes no backup: the backups directory keeps a bounded
// number, so every refusal would rotate a good restore point out.
func TestARefusedUpdateTakesNoBackup(t *testing.T) {
	dataDir := t.TempDir()
	hd := newHandler(testBackendAt(t, dataDir), "9.9.9", testDomain(t), nil, Deployment{DataDir: dataDir, UpdateDir: t.TempDir()})
	trusted := updatesig.TrustedKeys
	updatesig.TrustedKeys = []string{base64.StdEncoding.EncodeToString(testReleaseKey.Public().(ed25519.PublicKey))}
	t.Cleanup(func() { updatesig.TrustedKeys = trusted })
	h := hd.routes()
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	body := elfBody(4096)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	rec := postUpdateSigned(t, h, testToken, testAdminPassword, nextCode(t, secret), body, testSignature(other, "9.9.9", runtime.GOARCH, body))
	if rec.Code != 400 {
		t.Fatalf("update = %d %s, want the signature refused", rec.Code, rec.Body)
	}
	if b := metadb.NewestBackup(filepath.Join(dataDir, "backups")); b != "" {
		t.Fatalf("a refused update wrote the backup %s", b)
	}
}

// A filesystem failure while staging answers a sentence that names no path
// on the box.
func TestAStagingFailureNamesNoPath(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "update")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	hd := newHandler(testBackend(t), "9.9.9", testDomain(t), nil, Deployment{UpdateDir: notADir})
	h := hd.routes()
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	rec := postUpdate(t, h, testToken, testAdminPassword, nextCode(t, secret), elfBody(64))
	if rec.Code != 500 {
		t.Fatalf("update = %d %s, want 500", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), notADir) || strings.Contains(rec.Body.String(), "not a directory") {
		t.Fatalf("the answer carries the filesystem error: %s", rec.Body)
	}
}

// The self-updater stages through the same function the route uses: a
// signed binary lands as the installer's pair, a database backup first.
func TestStageReleaseStagesAVerifiedBinary(t *testing.T) {
	_, dir := updateAPI(t)
	h := newHandler(testBackend(t), "9.9.9", testDomain(t), nil, Deployment{})
	h.dep.UpdateDir = dir
	body := elfBody(64)
	if err := h.stageRelease(body, testSignature(testReleaseKey, "9.9.9", runtime.GOARCH, body)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, stagedName)); err != nil {
		t.Fatalf("nothing staged: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, stagedSigName)); err != nil {
		t.Fatalf("no signature staged: %v", err)
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	if err := h.stageRelease(body, testSignature(other, "9.9.9", runtime.GOARCH, body)); err == nil {
		t.Fatal("a foreign signature staged")
	}
}
