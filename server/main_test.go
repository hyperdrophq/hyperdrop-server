package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/selfupdate"
	"hyperdrop/server/internal/totp"

	_ "modernc.org/sqlite"
)

func TestRunCheckSchema(t *testing.T) {
	// A fresh directory: the database is created and opens.
	if code := runCheck("checkschema", t.TempDir(), false); code != 0 {
		t.Fatalf("fresh dir exit = %d, want 0", code)
	}
	// A database this server did not create (stamp 0, but holding tables): 1.
	foreign := t.TempDir()
	foreignDB, err := sql.Open("sqlite", "file:"+filepath.Join(foreign, metadb.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreignDB.Exec(`CREATE TABLE stranger (x)`); err != nil {
		t.Fatal(err)
	}
	foreignDB.Close()
	if code := runCheck("checkschema", foreign, false); code != 1 {
		t.Fatalf("foreign database exit = %d, want 1", code)
	}
	// A stamp newer than this binary knows: 3, so the provisioner refuses the
	// downgrade while the running server is still serving.
	newer := t.TempDir()
	stampUserVersion(t, filepath.Join(newer, metadb.FileName), 99)
	if code := runCheck("checkschema", newer, false); code != 3 {
		t.Fatalf("newer stamp exit = %d, want 3", code)
	}
}

// stampUserVersion writes a schema stamp straight into a new database file,
// which is the only way to produce a volume this binary considers too new.
func stampUserVersion(t *testing.T, path string, v int) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v)); err != nil {
		t.Fatal(err)
	}
}

func TestRunResetAdminSetsThePassword(t *testing.T) {
	dir := t.TempDir()
	db, err := metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureAdmin("root", "first-password"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	seed := filepath.Join(t.TempDir(), "admin-password.seed")
	if err := os.WriteFile(seed, []byte("second-password"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runResetAdmin(dir, "", seed); code != 0 {
		t.Fatalf("resetadmin exit = %d, want 0", code)
	}
	// The seed is gone once read: the password does not outlive the command.
	if _, err := os.Lstat(seed); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the seed is still on disk: %v", err)
	}
	db, err = metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// The sole admin is the one reset, under its own name rather than the
	// default one, and the new password is what logs in.
	if _, err := db.Authenticate("root", "second-password"); err != nil {
		t.Fatalf("the reset password does not log in: %v", err)
	}
	if _, err := db.Authenticate("root", "first-password"); err == nil {
		t.Fatal("the replaced password still logs in")
	}
}

// No seed, a missing seed and an empty one are each refused before the
// volume is opened at all, so a mis-configured run cannot blank an
// administrator.
func TestRunResetAdminRefusesAnEmptyPassword(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.seed")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, seed := range map[string]string{
		"no seed named":  "",
		"a missing seed": filepath.Join(t.TempDir(), "absent.seed"),
		"an empty seed":  empty,
	} {
		dir := t.TempDir()
		if code := runResetAdmin(dir, "", seed); code != 2 {
			t.Errorf("%s: exit = %d, want 2", name, code)
		}
		if _, err := os.Lstat(filepath.Join(dir, metadb.FileName)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: the volume was opened: %v", name, err)
		}
	}
}

// captureOutput runs fn with the process's standard output and standard
// error redirected into pipes and returns what fn wrote to each. The
// subcommands print straight to os.Stdout and os.Stderr, which is what
// their callers read over SSH.
func captureOutput(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	savedOut, savedErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	defer func() { os.Stdout, os.Stderr = savedOut, savedErr }()
	fn()
	outW.Close()
	errW.Close()
	o, err := io.ReadAll(outR)
	if err != nil {
		t.Fatal(err)
	}
	e, err := io.ReadAll(errR)
	if err != nil {
		t.Fatal(err)
	}
	outR.Close()
	errR.Close()
	return string(o), string(e)
}

func TestRunAdminsListsAdminsAndIsSilentWithoutADatabase(t *testing.T) {
	// A directory that holds no database answers nothing and exits 0: the
	// probe runs against boxes that have never had a server, and it must
	// leave nothing behind on one an install then abandons.
	empty := t.TempDir()
	exit := -1
	out, errOut := captureOutput(t, func() { exit = runAdmins(empty, nil) })
	if exit != 0 || out != "" || errOut != "" {
		t.Fatalf("empty dir: exit %d, stdout %q, stderr %q", exit, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(empty, metadb.FileName)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the probe created a database: %v", err)
	}

	// One administrator beside an ordinary account: the admin alone.
	dir := t.TempDir()
	db, err := metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureAdmin("dmitry", "pw"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser("bob", "pw", metadb.RoleUser, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	out, errOut = captureOutput(t, func() { exit = runAdmins(dir, nil) })
	if exit != 0 || out != "dmitry\n" || errOut != "" {
		t.Fatalf("one admin: exit %d, stdout %q, stderr %q", exit, out, errOut)
	}

	// Two administrators: one name per line, sorted.
	db, err = metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser("carol", "pw", metadb.RoleAdmin, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	out, errOut = captureOutput(t, func() { exit = runAdmins(dir, nil) })
	if exit != 0 || out != "carol\ndmitry\n" || errOut != "" {
		t.Fatalf("two admins: exit %d, stdout %q, stderr %q", exit, out, errOut)
	}
}

// --standing adds whether each administrator can sign in: the DSM page's
// admin rescue labels the ones that cannot.
func TestRunAdminsStandingNamesAdminsThatCannotSignIn(t *testing.T) {
	dir := t.TempDir()
	db, err := metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureAdmin("dmitry", "pw"); err != nil {
		t.Fatal(err)
	}
	yes, past := true, time.Now().Add(-time.Hour)
	for name, s := range map[string]metadb.Settings{
		"carol": {Disabled: &yes},
		"erin":  {AccountExpiresAt: &past},
		"frank": {Disabled: &yes, AccountExpiresAt: &past},
	} {
		if _, err := db.CreateUser(name, "pw", metadb.RoleAdmin, s); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.CreateUser("bob", "pw", metadb.RoleUser, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	exit := -1
	out, errOut := captureOutput(t, func() { exit = runAdmins(dir, []string{"--standing"}) })
	if want := "carol\tsuspended\ndmitry\tactive\nerin\texpired\nfrank\tsuspended\n"; exit != 0 || out != want || errOut != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", exit, out, errOut)
	}
	out, _ = captureOutput(t, func() { exit = runAdmins(dir, []string{"--nope"}) })
	if exit != 2 || out != "" {
		t.Fatalf("unknown flag: exit %d, stdout %q", exit, out)
	}
}

func TestRunReset2FADisablesAFactorAndReportsAlreadyOff(t *testing.T) {
	dir := t.TempDir()
	db, err := metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureAdmin("dmitry", "pw"); err != nil {
		t.Fatal(err)
	}
	secret, err := db.StartTOTP("dmitry")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	otp, err := totp.Code(secret, totp.StepAt(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ConfirmTOTP("dmitry", otp, now); err != nil {
		t.Fatal(err)
	}
	u, err := db.User("dmitry")
	if err != nil {
		t.Fatal(err)
	}
	if !u.TwoFactorEnabled() || u.RecoveryCodesLeft == 0 {
		t.Fatalf("the enrolment did not take: enabled=%v codes=%d", u.TwoFactorEnabled(), u.RecoveryCodesLeft)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	exit := -1
	out, errOut := captureOutput(t, func() { exit = runReset2FA(dir, "dmitry") })
	if exit != 0 || out != "RESET2FA-DONE\n" || errOut != "" {
		t.Fatalf("reset: exit %d, stdout %q, stderr %q", exit, out, errOut)
	}
	db, err = metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if u, err = db.User("dmitry"); err != nil {
		t.Fatal(err)
	}
	if u.TwoFactorEnabled() || u.TOTPStored != "" || u.RecoveryCodesLeft != 0 {
		t.Fatalf("the factor survived: enabled=%v secret=%q codes=%d", u.TwoFactorEnabled(), u.TOTPStored, u.RecoveryCodesLeft)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// A second run answers the marker the client maps onto "already off".
	out, errOut = captureOutput(t, func() { exit = runReset2FA(dir, "dmitry") })
	if exit != 0 || out != "RESET2FA-ALREADY-OFF\n" || errOut != "" {
		t.Fatalf("second run: exit %d, stdout %q, stderr %q", exit, out, errOut)
	}

	// An account the volume does not hold gets its own exit code, so the
	// client can name it rather than reporting a failure.
	out, errOut = captureOutput(t, func() { exit = runReset2FA(dir, "nobody") })
	if exit != 4 || out != "" {
		t.Fatalf("unknown account: exit %d, stdout %q", exit, out)
	}
	if !strings.Contains(errOut, "no account nobody") {
		t.Errorf("stderr does not name the account: %q", errOut)
	}

	// A missing or malformed account is refused before anything is opened.
	fresh := t.TempDir()
	for _, bad := range []string{"", "../x"} {
		out, errOut = captureOutput(t, func() { exit = runReset2FA(fresh, bad) })
		if exit != 2 || out != "" {
			t.Fatalf("account %q: exit %d, stdout %q", bad, exit, out)
		}
		if !strings.Contains(errOut, "usage") {
			t.Errorf("account %q: stderr does not carry the usage line: %q", bad, errOut)
		}
	}
	if _, err := os.Stat(filepath.Join(fresh, metadb.FileName)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused account opened a database: %v", err)
	}
}

func TestRunCheckDBAnswersOkAndFailsOnACorruptFile(t *testing.T) {
	exit := -1
	out, errOut := captureOutput(t, func() { exit = runCheck("checkdb", t.TempDir(), true) })
	if exit != 0 || out != "ok\n" || errOut != "" {
		t.Fatalf("fresh dir: exit %d, stdout %q, stderr %q", exit, out, errOut)
	}

	// A database whose pages are gone is what an operator suspecting the
	// volume runs this for.
	dir := t.TempDir()
	db, err := metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, metadb.FileName), make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errOut = captureOutput(t, func() { exit = runCheck("checkdb", dir, true) })
	if exit != 1 || out != "" {
		t.Fatalf("corrupt file: exit %d, stdout %q", exit, out)
	}
	if errOut == "" {
		t.Error("a corrupt database was refused without a message")
	}
}

func TestResolveBoot(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	t.Run("overrides", func(t *testing.T) {
		bc, err := resolveBoot(env(map[string]string{
			"HYPERDROP_DOMAIN": "share.example.com", "HYPERDROP_IP": "203.0.113.7",
			"HYPERDROP_PLATFORM": "dsm7", "HYPERDROP_LIVE_SHARE_GRACE": "3s",
			"HYPERDROP_ABANDONED_UPLOAD_TTL": "45m"}))
		if err != nil {
			t.Fatal(err)
		}
		if bc.Platform != "dsm7" || bc.LiveShareGrace != 3*time.Second || bc.AbandonedWindow != 45*time.Minute {
			t.Fatalf("overrides = %q %v %v", bc.Platform, bc.LiveShareGrace, bc.AbandonedWindow)
		}
	})
	t.Run("a bad duration keeps the default", func(t *testing.T) {
		for _, v := range []string{"", "nonsense", "-1h", "0s"} {
			if d := positiveDuration(v); d != 0 {
				t.Errorf("positiveDuration(%q) = %v, want 0", v, d)
			}
		}
	})
	t.Run("defaults", func(t *testing.T) {
		bc, err := resolveBoot(env(map[string]string{
			"HYPERDROP_DOMAIN": "share.example.com", "HYPERDROP_IP": "203.0.113.7"}))
		if err != nil {
			t.Fatal(err)
		}
		if bc.HTTPAddr != ":80" || bc.HTTPSAddr != ":443" {
			t.Fatalf("default addrs = %q %q", bc.HTTPAddr, bc.HTTPSAddr)
		}
	})
	t.Run("alternate ports", func(t *testing.T) {
		bc, err := resolveBoot(env(map[string]string{
			"HYPERDROP_DOMAIN": "share.example.com", "HYPERDROP_IP": "203.0.113.7",
			"HYPERDROP_HTTP_ADDR": ":5080", "HYPERDROP_HTTPS_ADDR": ":5443"}))
		if err != nil {
			t.Fatal(err)
		}
		if bc.HTTPAddr != ":5080" || bc.HTTPSAddr != ":5443" {
			t.Fatalf("addrs = %q %q", bc.HTTPAddr, bc.HTTPSAddr)
		}
	})
	t.Run("behind NAT needs no IP", func(t *testing.T) {
		bc, err := resolveBoot(env(map[string]string{
			"HYPERDROP_DOMAIN": "share.example.com", "HYPERDROP_BEHIND_NAT": "1"}))
		if err != nil {
			t.Fatal(err)
		}
		if bc.PublicIP != "" || bc.Domain != "share.example.com" {
			t.Fatalf("bc = %+v", bc)
		}
	})
	t.Run("domain without IP and without NAT flag is refused", func(t *testing.T) {
		if _, err := resolveBoot(env(map[string]string{
			"HYPERDROP_DOMAIN": "share.example.com"})); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("no domain and no allow-private is refused", func(t *testing.T) {
		if _, err := resolveBoot(env(map[string]string{})); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("invalid domain is refused even behind NAT", func(t *testing.T) {
		if _, err := resolveBoot(env(map[string]string{
			"HYPERDROP_DOMAIN": "not a domain", "HYPERDROP_BEHIND_NAT": "1"})); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("the names service URL", func(t *testing.T) {
		for _, tc := range []struct {
			raw, want    string
			allowPrivate bool
		}{
			{"", ddns.DefaultBaseURL, false},
			{"https://names.example.com/", "https://names.example.com", false},
			{"https://names.example.com/base", "https://names.example.com/base", false},
			{"http://127.0.0.1:8090", "http://127.0.0.1:8090", false},
			{"http://localhost:8090", "http://localhost:8090", false},
			{"http://names.lan:8090", "http://names.lan:8090", true},
			{"http://names.example.com", "", false},
			{"ftp://names.example.com", "", false},
			{"https://user:pw@names.example.com", "", false},
			{"https://names.example.com/?a=b", "", false},
			{"names.example.com", "", false},
		} {
			m := map[string]string{"HYPERDROP_DOMAIN": "share.example.com", "HYPERDROP_IP": "203.0.113.7",
				"HYPERDROP_NAMES_URL": tc.raw}
			if tc.allowPrivate {
				m["HYPERDROP_ALLOW_PRIVATE"] = "1"
			}
			bc, err := resolveBoot(env(m))
			if tc.want == "" {
				if err == nil {
					t.Errorf("HYPERDROP_NAMES_URL=%q accepted as %q, want a refusal", tc.raw, bc.NamesURL)
				}
				continue
			}
			if err != nil || bc.NamesURL != tc.want {
				t.Errorf("HYPERDROP_NAMES_URL=%q = %q, %v; want %q", tc.raw, bc.NamesURL, err, tc.want)
			}
		}
	})
	t.Run("a private HYPERDROP_IP is refused with a domain", func(t *testing.T) {
		if _, err := resolveBoot(env(map[string]string{
			"HYPERDROP_DOMAIN": "share.example.com", "HYPERDROP_IP": "192.168.1.5"})); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestCertSubjects(t *testing.T) {
	got := certSubjects("share.example.com", "203.0.113.7")
	want := []string{"share.example.com", "203.0.113.7"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v", got)
	}
	got = certSubjects("share.example.com", "")
	if len(got) != 1 {
		t.Fatalf("behind NAT: got %v, want the domain alone", got)
	}
}

func TestIsPublicIPv4Boundaries(t *testing.T) {
	for ip, want := range map[string]bool{
		"203.0.113.7":     true, // TEST-NET-3, which the check counts as public
		"8.8.8.8":         true,
		"100.63.255.255":  true,  // just below CGNAT
		"100.64.0.0":      false, // CGNAT start
		"100.127.255.255": false, // CGNAT end
		"100.128.0.0":     true,  // just above CGNAT
		"172.15.0.1":      true,  // below 172.16/12
		"172.16.0.1":      false,
		"172.31.255.255":  false,
		"172.32.0.1":      true, // above 172.16/12
		"0.0.0.0":         false,
		"0.1.2.3":         false, // 0/8 this-network
		"223.255.255.255": true,  // top of unicast space
		"240.0.0.1":       false, // class E reserved
		"255.255.255.255": false, // broadcast
	} {
		if got := isPublicIPv4(ip); got != want {
			t.Errorf("isPublicIPv4(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestAFreeNameSuppliesTheDomain(t *testing.T) {
	env := map[string]string{
		"HYPERDROP_DDNS_NAME":  "alice",
		"HYPERDROP_BEHIND_NAT": "1",
	}
	bc, err := resolveBoot(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("resolveBoot: %v", err)
	}
	if bc.DDNSName != "alice" {
		t.Errorf("DDNSName = %q, want alice", bc.DDNSName)
	}
	// Everything downstream reads Domain, so the free name has to supply it
	// rather than being a second source of truth beside it.
	if bc.Domain != "alice.hyperdrop.link" {
		t.Errorf("Domain = %q, want alice.hyperdrop.link", bc.Domain)
	}
}

// Two sources of truth for one domain is a configuration that cannot be
// obeyed, so it is refused rather than silently preferring one.
func TestAFreeNameAndADomainTogetherAreRefused(t *testing.T) {
	env := map[string]string{
		"HYPERDROP_DDNS_NAME":  "alice",
		"HYPERDROP_DOMAIN":     "share.example.com",
		"HYPERDROP_BEHIND_NAT": "1",
	}
	_, err := resolveBoot(func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("a name and a domain together were accepted")
	}
	if !strings.Contains(err.Error(), "HYPERDROP_DDNS_NAME") {
		t.Errorf("error does not name the conflicting variable: %v", err)
	}
}

func TestAMalformedFreeNameIsRefusedAtBoot(t *testing.T) {
	for _, name := range []string{"bob", "Alice", "al_ice", "-alice", "alice-", "al--ice",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		env := map[string]string{"HYPERDROP_DDNS_NAME": name, "HYPERDROP_BEHIND_NAT": "1"}
		if _, err := resolveBoot(func(k string) string { return env[k] }); err == nil {
			t.Errorf("name %q was accepted", name)
		}
	}
}

func TestNoFreeNameLeavesTheDomainAlone(t *testing.T) {
	env := map[string]string{"HYPERDROP_DOMAIN": "share.example.com", "HYPERDROP_BEHIND_NAT": "1"}
	bc, err := resolveBoot(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("resolveBoot: %v", err)
	}
	if bc.DDNSName != "" || bc.Domain != "share.example.com" {
		t.Fatalf("got DDNSName=%q Domain=%q", bc.DDNSName, bc.Domain)
	}
}

// A free name with no IP and no HYPERDROP_BEHIND_NAT is refused for needing
// HYPERDROP_IP, and the error must name the variable the operator actually
// set rather than the HYPERDROP_DOMAIN they never touched.
func TestAFreeNameNeedingIPNamesItselfNotDomain(t *testing.T) {
	env := map[string]string{"HYPERDROP_DDNS_NAME": "alice"}
	_, err := resolveBoot(func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "HYPERDROP_DDNS_NAME=alice") {
		t.Errorf("error does not name HYPERDROP_DDNS_NAME: %v", err)
	}
	if strings.Contains(err.Error(), "HYPERDROP_DOMAIN=") {
		t.Errorf("error names HYPERDROP_DOMAIN, which this operator never set: %v", err)
	}
}

// checkschema refuses a volume stamped by an older major version: the
// provisioner stops an update there instead of starting a server that cannot
// open the data.
func TestRunCheckSchemaRefusesAnOlderMajorVolume(t *testing.T) {
	dir := t.TempDir()
	db, err := metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	raw, err := sql.Open("sqlite", filepath.Join(dir, metadb.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`PRAGMA user_version = 6`); err != nil {
		t.Fatal(err)
	}
	if code := runCheck("checkschema", dir, false); code == 0 {
		t.Fatal("checkschema accepted a stamp-6 volume")
	}
}

func TestTheHTTPSListenerRefusesTLSBelow12(t *testing.T) {
	cfg := httpsTLSConfig(&tls.Config{NextProtos: []string{"acme-tls/1"}}, nil)
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %#x, want TLS 1.2", cfg.MinVersion)
	}
	if want := []string{"h2", "http/1.1", "acme-tls/1"}; !slices.Equal(cfg.NextProtos, want) {
		t.Fatalf("NextProtos = %v, want %v", cfg.NextProtos, want)
	}
}

// Port 80 sends a request to the domain the server holds when it arrives: a domain set at
// runtime replaces the boot domain as the target, its own two names keep
// their host in any spelling, and nothing else is ever a target.
func TestPort80RedirectsToTheCurrentDomain(t *testing.T) {
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	h := redirectToHTTPS(dom, "boot.example.com")
	redirect := func(host string) string {
		r := httptest.NewRequest("GET", "/share/abc?x=1", nil)
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusPermanentRedirect {
			t.Fatalf("Host %q: status %d", host, w.Code)
		}
		return w.Header().Get("Location")
	}
	if got := redirect("203.0.113.7"); got != "https://boot.example.com/share/abc?x=1" {
		t.Fatalf("no current domain: %q, want the boot domain", got)
	}
	if err := dom.Adopt("new.example.com"); err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{
		"203.0.113.7":              "https://new.example.com/share/abc?x=1",
		"203.0.113.7:80":           "https://new.example.com/share/abc?x=1",
		"boot.example.com":         "https://new.example.com/share/abc?x=1",
		"evil.example":             "https://new.example.com/share/abc?x=1",
		"new.example.com":          "https://new.example.com/share/abc?x=1",
		"New.Example.COM.":         "https://new.example.com/share/abc?x=1",
		"files.new.example.com":    "https://files.new.example.com/share/abc?x=1",
		"FILES.new.example.com:80": "https://files.new.example.com/share/abc?x=1",
		"files.boot.example.com":   "https://new.example.com/share/abc?x=1",
	} {
		if got := redirect(host); got != want {
			t.Errorf("Host %q: %q, want %q", host, got, want)
		}
	}
}

// A names service that never answers holds the boot for the limit at most,
// and the claim it cut short stays pending for the update loop to finish.
func TestTheBootClaimIsBounded(t *testing.T) {
	release := make(chan struct{})
	names := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer names.Close()
	defer close(release)
	store, err := ddns.Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	client := &ddns.Client{BaseURL: names.URL}
	updater := ddns.NewUpdater(store, client, func(context.Context) (string, bool) { return "", false })
	start := time.Now()
	err = bootTake(context.Background(), updater, "alice", "server-id", 200*time.Millisecond)
	if err == nil {
		t.Fatal("a claim the names service never answered succeeded")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the boot claim took %v, want about the 200 ms limit", took)
	}
	if st := store.Snapshot(); !st.Pending || st.Name != "alice" {
		t.Fatalf("state after the cut-short claim = %+v, want alice pending", st)
	}
}

// A new volume records its install's automatic-update choice with its first
// administrator; a volume that already has one keeps its switch, so a box
// installed before the choice existed keeps updating itself.
func TestOnlyANewVolumeRecordsTheAutomaticUpdateChoice(t *testing.T) {
	t.Setenv("HYPERDROP_ADMIN_USER", "owner")
	for _, on := range []bool{false, true} {
		t.Setenv("HYPERDROP_ADMIN_PASSWORD", "pw")
		db, err := metadb.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := seedAdmin(db, on); err != nil {
			t.Fatal(err)
		}
		if got, err := selfupdate.AutoIn(db); err != nil || got != on {
			t.Errorf("a new volume installed with %v: automatic updates %v, %v", on, got, err)
		}
		db.Close()
	}
	db, err := metadb.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.EnsureAdmin("owner", "pw"); err != nil {
		t.Fatal(err)
	}
	if err := seedAdmin(db, false); err != nil {
		t.Fatal(err)
	}
	if got, err := selfupdate.AutoIn(db); err != nil || !got {
		t.Errorf("a volume that already had an administrator: automatic updates %v, %v; want on", got, err)
	}
}

// auto-update prints the switch, turns it on or off, and never creates a
// database.
func TestRunAutoUpdateReadsAndTurnsTheSwitch(t *testing.T) {
	was := official
	official = "true"
	t.Cleanup(func() { official = was })
	empty := t.TempDir()
	exit := -1
	_, errOut := captureOutput(t, func() { exit = runAutoUpdate(empty, nil) })
	if exit != 1 || !strings.Contains(errOut, "no HyperDrop database") {
		t.Fatalf("no database: exit %d, stderr %q", exit, errOut)
	}
	if _, err := os.Stat(filepath.Join(empty, metadb.FileName)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the command created a database: %v", err)
	}
	dir := t.TempDir()
	db, err := metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureAdmin("owner", "pw"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		args []string
		want string
	}{{nil, "on\n"}, {[]string{"off"}, "off\n"}, {nil, "off\n"}, {[]string{"on"}, "on\n"}, {nil, "on\n"}} {
		out, errOut := captureOutput(t, func() { exit = runAutoUpdate(dir, step.args) })
		if exit != 0 || out != step.want || errOut != "" {
			t.Fatalf("%v: exit %d, stdout %q, stderr %q; want %q", step.args, exit, out, errOut, step.want)
		}
	}
	for _, args := range [][]string{{"yes"}, {"on", "off"}} {
		_, errOut := captureOutput(t, func() { exit = runAutoUpdate(dir, args) })
		if exit != 2 || !strings.Contains(errOut, "usage") {
			t.Errorf("%v: exit %d, stderr %q", args, exit, errOut)
		}
	}

	// A build that is not official says why and turns nothing.
	official = ""
	out, _ := captureOutput(t, func() { exit = runAutoUpdate(dir, nil) })
	if exit != 0 || out != "on\nunavailable: "+notOfficialUpdates+"\n" {
		t.Fatalf("not official: exit %d, stdout %q", exit, out)
	}
	_, errOut = captureOutput(t, func() { exit = runAutoUpdate(dir, []string{"off"}) })
	if exit != 3 || !strings.Contains(errOut, "not an official") {
		t.Fatalf("not official, off: exit %d, stderr %q", exit, errOut)
	}
	if out, _ := captureOutput(t, func() { exit = runAutoUpdate(dir, nil) }); !strings.HasPrefix(out, "on\n") {
		t.Fatalf("a refused switch changed the volume: %q", out)
	}
}

// The first admin is seeded from the environment once, and the password
// leaves the environment with it.
func TestSeedingTheAdminDropsThePasswordFromTheEnvironment(t *testing.T) {
	db, err := metadb.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	t.Setenv("HYPERDROP_ADMIN_USER", "owner")
	t.Setenv("HYPERDROP_ADMIN_PASSWORD", `a\b"c `)
	if err := seedAdmin(db, true); err != nil {
		t.Fatal(err)
	}
	if v, set := os.LookupEnv("HYPERDROP_ADMIN_PASSWORD"); set {
		t.Fatalf("HYPERDROP_ADMIN_PASSWORD is still %q", v)
	}
	if names, err := db.AdminNames(); err != nil || len(names) != 1 || names[0] != "owner" {
		t.Fatalf("admins = %v, %v", names, err)
	}
}

// A seed file is the password the first boot reads and then removes, so the
// password never enters the server's environment; a seed meeting a volume
// that already has an administrator changes nothing and is removed too.
func TestTheAdminSeedFileIsReadOnceAndRemoved(t *testing.T) {
	dir := t.TempDir()
	db, err := metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seed := filepath.Join(dir, "admin-password.seed")
	if err := os.WriteFile(seed, []byte(`p a\ss"`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HYPERDROP_ADMIN_USER", "owner")
	t.Setenv("HYPERDROP_ADMIN_PASSWORD", "")
	t.Setenv("HYPERDROP_ADMIN_PASSWORD_FILE", seed)
	if err := seedAdmin(db, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(seed); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the seed is still on disk: %v", err)
	}
	if _, err := db.Authenticate("owner", `p a\ss"`); err != nil {
		t.Fatalf("the seeded password does not sign in: %v", err)
	}
	// A reinstall over kept data: the new seed is ignored and removed.
	if err := os.WriteFile(seed, []byte("another"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := seedAdmin(db, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(seed); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the ignored seed is still on disk: %v", err)
	}
	if _, err := db.Authenticate("owner", "another"); err == nil {
		t.Fatal("a seed over an existing administrator changed the password")
	}
	// No seed file at all: the password comes from the environment.
	if err := seedAdmin(db, true); err != nil {
		t.Fatalf("no seed file: %v", err)
	}
}

// A seed the server cannot read stops no boot of a volume that already has
// an administrator, which never needs it: the boot goes on and removes it.
// The first boot of an empty volume, whose admin it would create, refuses
// with the reason.
func TestAnUnreadableSeedStopsOnlyTheFirstBoot(t *testing.T) {
	dir := t.TempDir()
	db, err := metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seed := filepath.Join(dir, "admin-password.seed")
	if err := os.Mkdir(seed, 0o700); err != nil { // a directory reads as an error
		t.Fatal(err)
	}
	t.Setenv("HYPERDROP_ADMIN_USER", "owner")
	t.Setenv("HYPERDROP_ADMIN_PASSWORD", "from-the-environment")
	t.Setenv("HYPERDROP_ADMIN_PASSWORD_FILE", seed)
	if err := seedAdmin(db, true); err == nil || !strings.Contains(err.Error(), "admin password seed") {
		t.Fatalf("the first boot with an unreadable seed: %v, want the seed named", err)
	}
	if names, _ := db.AdminNames(); len(names) != 0 {
		t.Fatalf("an admin was created around the seed: %v", names)
	}
	if err := db.EnsureAdmin("owner", "kept-password"); err != nil {
		t.Fatal(err)
	}
	if err := seedAdmin(db, true); err != nil {
		t.Fatalf("a boot with an administrator stopped on the seed: %v", err)
	}
	if _, err := os.Stat(seed); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the ignored seed is still on disk: %v", err)
	}
}
