package dsmpage

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/totp"
)

var (
	buildServerOnce sync.Once
	builtServer     string
	buildServerErr  error
)

// serverBinary builds the server once for the package's tests: rescue runs
// its admins, resetadmin and reset2fa subcommands as programs.
func serverBinary(t *testing.T) string {
	t.Helper()
	buildServerOnce.Do(func() {
		dir, err := os.MkdirTemp("", "dsmpage-server-")
		if err != nil {
			buildServerErr = err
			return
		}
		builtServer = filepath.Join(dir, "hyperdrop-server")
		cmd := exec.Command("go", "build", "-o", builtServer, ".")
		cmd.Dir = ".."
		if out, err := cmd.CombinedOutput(); err != nil {
			buildServerErr = &buildError{err, string(out)}
		}
	})
	if buildServerErr != nil {
		t.Fatal(buildServerErr)
	}
	return builtServer
}

type buildError struct {
	err error
	out string
}

func (e *buildError) Error() string { return "building the server: " + e.err.Error() + "\n" + e.out }

func TestMain(m *testing.M) {
	code := m.Run()
	if builtServer != "" {
		os.RemoveAll(filepath.Dir(builtServer))
	}
	os.Exit(code)
}

const (
	oldPassword = "the-old-password"
	newPassword = " a new password, kept byte for byte "
)

// rescueRig is a saveRig whose data folder holds a volume: the admins
// "admin" and "alice" (alice with a second factor), the user "bob", and a
// signed-in device for each.
type rescueRig struct {
	*saveRig
	data   string
	tokens map[string]string
	calls  string // what the wrapped server binary was run with, one line per run
}

func newRescueRig(t *testing.T) *rescueRig {
	t.Helper()
	r := &rescueRig{saveRig: newSaveRig(t, freeConf), tokens: map[string]string{}}
	data, err := filepath.EvalSymlinks(filepath.Join(r.root, "real"))
	if err != nil {
		t.Fatal(err)
	}
	r.data = data
	db, err := metadb.Open(r.data)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureAdmin("admin", oldPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser("alice", oldPassword, metadb.RoleAdmin, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser("bob", oldPassword, metadb.RoleUser, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	secret, err := db.StartTOTP("alice")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	otp, err := totp.Code(secret, totp.StepAt(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ConfirmTOTP("alice", otp, now); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"admin", "alice", "bob"} {
		if r.tokens[name], err = db.MintToken(name, "phone"); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	r.wrap("")
	return r
}

// wrap makes the page's server binary a script that records each run's
// arguments and environment, then runs before (shell code that may end
// the run) and the real server.
func (r *rescueRig) wrap(before string) {
	r.t.Helper()
	r.calls = filepath.Join(r.root, "calls")
	r.deps.ServerBinary = writeScript(r.t, `{ printf 'args:%s\n' "$*"; env | sort | sed 's/^/env:/'; } >> '`+r.calls+`'
`+before+`
exec '`+serverBinary(r.t)+`' "$@"
`)
}

func (r *rescueRig) runs() string {
	b, _ := os.ReadFile(r.calls)
	return string(b)
}

func (r *rescueRig) postRescue(body string) *httptest.ResponseRecorder {
	r.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/rescue", strings.NewReader(body))
	req.Header.Set("X-SYNO-TOKEN", "tok")
	w := httptest.NewRecorder()
	New(r.deps).ServeHTTP(w, req)
	return w
}

func (r *rescueRig) getRescue() *httptest.ResponseRecorder {
	r.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/rescue", nil)
	req.Header.Set("X-SYNO-TOKEN", "tok")
	w := httptest.NewRecorder()
	New(r.deps).ServeHTTP(w, req)
	return w
}

// rescue posts req and runs the worker it started.
func (r *rescueRig) rescue(req RescueRequest) LastChange {
	r.t.Helper()
	body, _ := json.Marshal(req)
	w := r.postRescue(string(body))
	if w.Code != http.StatusAccepted || strings.TrimSpace(w.Body.String()) != `{"state":"applying"}` {
		r.t.Fatalf("POST: %d %s", w.Code, w.Body)
	}
	if len(r.workers) != 1 {
		r.t.Fatalf("workers %v", r.workers)
	}
	res := r.page().apply(r.workers[0], r.svc, r.clk)
	r.lock.Close()
	return res
}

func (r *rescueRig) db() *metadb.DB {
	r.t.Helper()
	db, err := metadb.OpenAsIs(r.data)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { db.Close() })
	return db
}

// signedIn is true while the account's device token still works.
func (r *rescueRig) signedIn(db *metadb.DB, name string) bool {
	_, err := db.UserByToken(r.tokens[name], metadb.ClientInfo{})
	return err == nil
}

func (r *rescueRig) logsIn(db *metadb.DB, name, password string) bool {
	_, err := db.Authenticate(name, password)
	return err == nil
}

func twoFactor(t *testing.T, db *metadb.DB, name string) bool {
	t.Helper()
	u, err := db.User(name)
	if err != nil {
		t.Fatal(err)
	}
	return u.TwoFactorEnabled()
}

func TestRescueListsTheAdministrators(t *testing.T) {
	r := newRescueRig(t)
	db, err := metadb.OpenAsIs(r.data)
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	if _, err := db.CreateUser("carol", oldPassword, metadb.RoleAdmin, metadb.Settings{Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	w := r.getRescue()
	if want := `{"admins":[{"name":"admin","standing":"active"},{"name":"alice","standing":"active"},{"name":"carol","standing":"suspended"}]}`; w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != want {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if runs := r.runs(); !strings.Contains(runs, "args:admins --standing\n") || !strings.Contains(runs, "env:HYPERDROP_DATA="+r.data+"\n") {
		t.Fatalf("runs:\n%s", runs)
	}
	if len(r.svc.calls) != 0 {
		t.Fatalf("listing touched the server: %v", r.svc.calls)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/rescue", nil)
	req.Header.Set("X-SYNO-TOKEN", "tok")
	w = httptest.NewRecorder()
	New(r.deps).ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, POST" {
		t.Fatalf("PUT: %d Allow %q", w.Code, w.Header().Get("Allow"))
	}
}

// A name that is not an administrator now is refused before anything
// stops, so the page can never create an account or reset a user's.
func TestRescueRefusesANameThatIsNotAnAdministrator(t *testing.T) {
	r := newRescueRig(t)
	for _, name := range []string{"bob", "nobody"} {
		w := r.postRescue(`{"account":"` + name + `","password":"` + newPassword + `","clear2fa":true}`)
		if w.Code != http.StatusBadRequest || errorText(t, w) != name+" is not an administrator." {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body)
		}
		if res := r.page().Rescue(RescueRequest{Account: name, Password: newPassword, Clear2FA: true}, r.svc, r.clk); res.State != "failed" || res.Reason != name+" is not an administrator." {
			t.Fatalf("%s: worker %+v", name, res)
		}
	}
	if len(r.workers) != 0 || len(r.svc.calls) != 0 || r.exists("var/.dsmpage-job.json") {
		t.Fatalf("workers %v, service %v", r.workers, r.svc.calls)
	}
	if runs := r.runs(); strings.Contains(runs, "args:resetadmin") || strings.Contains(runs, "args:reset2fa") {
		t.Fatalf("runs:\n%s", runs)
	}
	db := r.db()
	if !r.logsIn(db, "bob", oldPassword) || !r.signedIn(db, "bob") {
		t.Fatal("bob's account changed")
	}
	if _, err := db.User("nobody"); err == nil {
		t.Fatal("nobody was created")
	}
	if !r.logsIn(db, "alice", oldPassword) || !twoFactor(t, db, "alice") {
		t.Fatal("alice changed")
	}
}

func TestRescueRefusesAPasswordTheServerRefuses(t *testing.T) {
	r := newRescueRig(t)
	for pw, want := range map[string]string{
		"short":                 "A password needs at least 8 characters.",
		strings.Repeat("x", 73): "A password can be at most 72 bytes long.",
	} {
		w := r.postRescue(`{"account":"alice","password":"` + pw + `","clear2fa":false}`)
		if w.Code != http.StatusBadRequest || errorText(t, w) != want {
			t.Fatalf("%q: %d %s", pw, w.Code, w.Body)
		}
	}
	for _, body := range []string{`{"account":"alice","password":"long enough","extra":1}`, `{"account":"alice"} {}`, `[]`} {
		if w := r.postRescue(body); w.Code != http.StatusBadRequest || errorText(t, w) != "The request is not valid." {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body)
		}
	}
	if len(r.workers) != 0 || len(r.svc.calls) != 0 || r.exists("var/last-change.json") {
		t.Fatal("a refused rescue started something")
	}
}

func TestRescueResetsThePasswordAndSignsTheAccountOut(t *testing.T) {
	r := newRescueRig(t)
	r.svc.onStop = func() {
		if r.exists("var/.dsmpage-job.json") {
			t.Error("the job, which holds the password, is still on disk when the server stops")
		}
	}
	body, _ := json.Marshal(RescueRequest{Account: "alice", Password: newPassword})
	w := r.postRescue(string(body))
	if w.Code != http.StatusAccepted {
		t.Fatalf("POST: %d %s", w.Code, w.Body)
	}
	job := filepath.Join(r.root, "var", ".dsmpage-job.json")
	if m := mode(t, job); m.Perm() != 0o600 || !m.IsRegular() {
		t.Fatalf("job mode %v", m)
	}
	if c := r.lastChange(); c.State != "applying" {
		t.Fatalf("last change %+v", c)
	}
	res := r.page().apply(job, r.svc, r.clk)
	r.lock.Close()
	if res.State != "done" || res.Reason != "Reset alice." || res.Text() != "Reset alice." {
		t.Fatalf("worker %+v", res)
	}
	if !slices.Equal(r.svc.calls, []string{"stop", "start"}) {
		t.Fatalf("service %v", r.svc.calls)
	}
	db := r.db()
	if !r.logsIn(db, "alice", newPassword) || r.logsIn(db, "alice", oldPassword) {
		t.Fatal("alice's password did not change")
	}
	if r.signedIn(db, "alice") {
		t.Fatal("alice's device is still signed in")
	}
	if !r.signedIn(db, "admin") || !r.signedIn(db, "bob") || !r.logsIn(db, "admin", oldPassword) {
		t.Fatal("another account changed")
	}
	if !twoFactor(t, db, "alice") {
		t.Fatal("the second factor went without being asked")
	}

	if s := r.get(); s.LastChange == nil || s.LastChange.State != "done" || s.LastChange.Text != "Reset alice." {
		t.Fatalf("state reports %+v", s.LastChange)
	}
	for _, name := range []string{".dsmpage-job.json", ".dsmpage-admin.seed"} {
		if r.exists("var/" + name) {
			t.Errorf("%s stayed", name)
		}
	}
	entries, _ := os.ReadDir(filepath.Join(r.root, "var"))
	for _, e := range entries {
		if b, _ := os.ReadFile(filepath.Join(r.root, "var", e.Name())); strings.Contains(string(b), strings.TrimSpace(newPassword)) {
			t.Errorf("var/%s holds the password", e.Name())
		}
	}

	runs := r.runs()
	if strings.Contains(runs, strings.TrimSpace(newPassword)) {
		t.Fatalf("the password reached an argument or the environment:\n%s", runs)
	}
	if strings.Contains(runs, "args:reset2fa") {
		t.Fatalf("reset2fa ran unasked:\n%s", runs)
	}
	for _, want := range []string{"args:resetadmin\n", "env:HYPERDROP_ADMIN_USER=alice\n",
		"env:HYPERDROP_ADMIN_PASSWORD_FILE=" + filepath.Join(r.root, "var", ".dsmpage-admin.seed") + "\n"} {
		if !strings.Contains(runs, want) {
			t.Fatalf("no %q in runs:\n%s", want, runs)
		}
	}
	// Each run's environment is PATH and HyperDrop's own variables.
	for _, line := range strings.Split(runs, "\n") {
		v, ok := strings.CutPrefix(line, "env:")
		if !ok {
			continue
		}
		if k, _, _ := strings.Cut(v, "="); k != "PATH" && k != "PWD" && k != "SHLVL" && k != "_" && k != "OLDPWD" && !strings.HasPrefix(k, "HYPERDROP_") {
			t.Errorf("the run's environment holds %s", k)
		}
	}
}

func TestRescueClearsTheSecondFactorWhenAsked(t *testing.T) {
	r := newRescueRig(t)
	if res := r.rescue(RescueRequest{Account: "alice", Password: newPassword, Clear2FA: true}); res.State != "done" || res.Reason != "Reset alice." {
		t.Fatalf("worker %+v", res)
	}
	db := r.db()
	if twoFactor(t, db, "alice") {
		t.Fatal("the second factor survived")
	}
	if !r.logsIn(db, "alice", newPassword) || r.signedIn(db, "alice") {
		t.Fatal("the password did not change")
	}
	if !strings.Contains(r.runs(), "args:reset2fa alice\n") {
		t.Fatalf("runs:\n%s", r.runs())
	}
	if !slices.Equal(r.svc.calls, []string{"stop", "start"}) {
		t.Fatalf("service %v", r.svc.calls)
	}
}

// A reset that fails after the stop still starts the server, and the
// reason is the subcommand's first line of error, never the password.
func TestRescueStartsTheServerEvenWhenTheResetFails(t *testing.T) {
	r := newRescueRig(t)
	r.wrap(`if [ "$1" = resetadmin ]; then printf 'resetadmin: the volume is busy (%s)\nmore detail\n' "$(cat "$HYPERDROP_ADMIN_PASSWORD_FILE")" >&2; exit 1; fi`)
	res := r.rescue(RescueRequest{Account: "alice", Password: newPassword, Clear2FA: true})
	if res.State != "failed" || !strings.HasPrefix(res.Reason, "HyperDrop could not reset the password: resetadmin: the volume is busy") {
		t.Fatalf("worker %+v", res)
	}
	if strings.Contains(res.Reason, strings.TrimSpace(newPassword)) || strings.Contains(res.Reason, "more detail") {
		t.Fatalf("reason %q", res.Reason)
	}
	if b := r.read("var/last-change.json"); strings.Contains(b, strings.TrimSpace(newPassword)) {
		t.Fatalf("last-change.json holds the password: %s", b)
	}
	if !slices.Equal(r.svc.calls, []string{"stop", "start"}) {
		t.Fatalf("service %v", r.svc.calls)
	}
	if r.exists("var/.dsmpage-admin.seed") {
		t.Fatal("the seed stayed")
	}
	if strings.Contains(r.runs(), "args:reset2fa") {
		t.Fatal("reset2fa ran after a failed reset")
	}
	db := r.db()
	if !r.logsIn(db, "alice", oldPassword) || !twoFactor(t, db, "alice") {
		t.Fatal("alice changed")
	}
}

func TestRescueReportsAServerThatDoesNotComeBack(t *testing.T) {
	r := newRescueRig(t)
	r.svc.starts = []startOutcome{{runs: true, healthy: false}}
	res := r.rescue(RescueRequest{Account: "admin", Password: newPassword})
	if res.State != "failed" || res.Reason != "Reset admin. HyperDrop did not start in 60 seconds." {
		t.Fatalf("worker %+v", res)
	}
	if !r.logsIn(r.db(), "admin", newPassword) {
		t.Fatal("the password did not change")
	}
}

func TestRescueRefusesALockedDataFolder(t *testing.T) {
	r := newRescueRig(t)
	if err := os.Remove(filepath.Join(r.root, "shares", "hyperdrop")); err != nil {
		t.Fatal(err)
	}
	const locked = "The HyperDrop folder is locked or missing. Unlock it in Control Panel, Shared Folder."
	if w := r.getRescue(); w.Code != http.StatusConflict || errorText(t, w) != locked {
		t.Fatalf("GET: %d %s", w.Code, w.Body)
	}
	if w := r.postRescue(`{"account":"admin","password":"` + newPassword + `","clear2fa":false}`); w.Code != http.StatusConflict || errorText(t, w) != locked {
		t.Fatalf("POST: %d %s", w.Code, w.Body)
	}
	if res := r.page().Rescue(RescueRequest{Account: "admin", Password: newPassword}, r.svc, r.clk); res.State != "failed" || res.Reason != locked {
		t.Fatalf("worker %+v", res)
	}
	if len(r.workers) != 0 || len(r.svc.calls) != 0 || r.runs() != "" {
		t.Fatal("a locked folder started something")
	}
}

func TestRescueWhileAChangeIsApplyingAnswers409(t *testing.T) {
	r := newRescueRig(t)
	lock, busy, err := takeLock(filepath.Join(r.root, "var", ".dsmpage.lock"))
	if err != nil || busy {
		t.Fatal(err, busy)
	}
	defer lock.Close()
	w := r.postRescue(`{"account":"admin","password":"` + newPassword + `","clear2fa":false}`)
	if w.Code != http.StatusConflict || errorText(t, w) != "Another change is being applied. Wait for it to finish." {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if len(r.workers) != 0 || r.exists("var/.dsmpage-job.json") || r.exists("var/last-change.json") {
		t.Fatal("a refused rescue left a job or a record")
	}
}

// The worker runs a Save job as before: a rescue job is told apart by its
// "job" field, which a Save job never carries.
func TestTheWorkerRefusesAJobOfAnUnknownKind(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.write("var/job.json", `{"job":"format","account":"admin"}`)
	if res := r.page().apply(filepath.Join(r.root, "var", "job.json"), r.svc, r.clk); res.State != "failed" {
		t.Fatalf("worker %+v", res)
	}
	if len(r.svc.calls) != 0 || r.exists("var/job.json") {
		t.Fatalf("service %v", r.svc.calls)
	}
}

// The account is checked again once the server is stopped, the moment
// before resetadmin, which creates an administrator for a name it does not
// know.
func TestRescueChecksTheAccountAgainOnceTheServerStops(t *testing.T) {
	r := newRescueRig(t)
	r.svc.onStop = func() {
		db, err := metadb.OpenAsIs(r.data)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if err := db.DeleteUser("alice"); err != nil {
			t.Fatal(err)
		}
	}
	res := r.rescue(RescueRequest{Account: "alice", Password: newPassword, Clear2FA: true})
	if res.State != "failed" || res.Reason != "alice is not an administrator." {
		t.Fatalf("worker %+v", res)
	}
	if !slices.Equal(r.svc.calls, []string{"stop", "start"}) {
		t.Fatalf("service %v", r.svc.calls)
	}
	if runs := r.runs(); strings.Contains(runs, "args:resetadmin") || strings.Contains(runs, "args:reset2fa") {
		t.Fatalf("runs:\n%s", runs)
	}
	if _, err := r.db().User("alice"); !errors.Is(err, metadb.ErrUserNotFound) {
		t.Fatalf("alice exists again: %v", err)
	}
	if r.exists("var/.dsmpage-admin.seed") {
		t.Fatal("a seed was written")
	}
}

// A password at the end of an error line, trailing spaces and all, is
// hidden before the line is trimmed.
func TestRescueHidesThePasswordAtTheEndOfAnErrorLine(t *testing.T) {
	r := newRescueRig(t)
	r.wrap(`if [ "$1" = resetadmin ]; then printf 'resetadmin: refused %s\n' "$(cat "$HYPERDROP_ADMIN_PASSWORD_FILE")" >&2; exit 1; fi`)
	res := r.rescue(RescueRequest{Account: "alice", Password: newPassword})
	if res.State != "failed" || res.Reason != "HyperDrop could not reset the password: resetadmin: refused [hidden]" {
		t.Fatalf("worker %+v", res)
	}
}

// A worker that died mid-change leaves neither its job nor the seed behind,
// since either may hold a password, and the page says which change it was.
func TestAnInterruptedChangeLeavesNoPasswordOnDisk(t *testing.T) {
	r := newRescueRig(t)
	r.write("var/last-change.json", `{"state":"applying","reason":"","at":1,"job":"rescue"}`)
	r.write("var/.dsmpage-job.json", `{"job":"rescue","account":"alice","password":"`+newPassword+`","clear2fa":false}`)
	r.write("var/.dsmpage-admin.seed", newPassword)
	s := r.get()
	if s.LastChange == nil || s.LastChange.State != "failed" || s.LastChange.Text != "Change failed: The reset was interrupted. Check the account and try again." {
		t.Fatalf("state reports %+v", s.LastChange)
	}
	if r.exists("var/.dsmpage-job.json") || r.exists("var/.dsmpage-admin.seed") {
		t.Fatal("the password stayed on disk")
	}

	// A Save keeps its own text, and only plain files are removed.
	other := filepath.Join(r.root, "elsewhere")
	r.write("elsewhere", "kept")
	if err := os.Symlink(other, filepath.Join(r.root, "var", ".dsmpage-job.json")); err != nil {
		t.Fatal(err)
	}
	r.write("var/last-change.json", `{"state":"applying","reason":"","at":1}`)
	if s := r.get(); s.LastChange == nil || s.LastChange.Reason != "The change was interrupted. Check the settings and save again." {
		t.Fatalf("state reports %+v", s.LastChange)
	}
	if !r.exists("var/.dsmpage-job.json") || r.read("elsewhere") != "kept" {
		t.Fatal("a link at the job's path was followed or removed")
	}
}

// While a worker holds the lock, its job and seed are its own.
func TestAChangeInProgressKeepsItsFiles(t *testing.T) {
	r := newRescueRig(t)
	lock, busy, err := takeLock(filepath.Join(r.root, "var", ".dsmpage.lock"))
	if err != nil || busy {
		t.Fatal(err, busy)
	}
	defer lock.Close()
	r.write("var/last-change.json", `{"state":"applying","reason":"","at":1,"job":"rescue"}`)
	r.write("var/.dsmpage-admin.seed", newPassword)
	if s := r.get(); s.LastChange == nil || s.LastChange.State != "applying" {
		t.Fatalf("state reports %+v", s.LastChange)
	}
	if !r.exists("var/.dsmpage-admin.seed") {
		t.Fatal("a running change lost its seed")
	}
}

func TestServerOutputIsBounded(t *testing.T) {
	var w capped
	w.Write([]byte(strings.Repeat("x", outputLimit+10)))
	if n, err := w.Write([]byte("y")); n != 1 || err != nil {
		t.Fatalf("write past the cap: %d, %v", n, err)
	}
	if w.String() != strings.Repeat("x", outputLimit) {
		t.Fatalf("kept %d bytes", len(w.String()))
	}
}

func TestRescueRefusesACommonPassword(t *testing.T) {
	r := newRescueRig(t)
	w := r.postRescue(`{"account":"alice","password":"password1","clear2fa":false}`)
	if w.Code != http.StatusBadRequest || errorText(t, w) != "This password is too common. Choose another." {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if len(r.workers) != 0 || len(r.svc.calls) != 0 {
		t.Fatal("a refused rescue started something")
	}
}
