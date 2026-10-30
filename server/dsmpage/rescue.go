package dsmpage

// Admin rescue, for when no app can sign in as an administrator. GET
// /api/rescue lists the volume's administrators; POST /api/rescue resets
// one of them: a new password, which signs the account out everywhere, and,
// when asked, no second factor. The reset is a job of kind "rescue" for the
// worker Save uses, under the same lock: it stops the server, runs the
// server binary's own resetadmin (and reset2fa) against the data folder and
// starts the server again. Every subcommand runs as this process's user,
// the package user, so the files SQLite keeps beside the database stay
// writable by the server.
//
// The password travels from the request to the job file and from the job
// file to resetadmin's one-shot seed, each mode 0600 in the package's var
// directory and removed once read. It is never an argument, an environment
// variable, a log line or a reason in last-change.json.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"hyperdrop/server/internal/conffile"
	"hyperdrop/server/internal/metadb"
)

const (
	// rescueJobKind is the job file's "job" for an admin rescue.
	rescueJobKind = "rescue"
	// subcommandLimit bounds one run of a server subcommand.
	subcommandLimit = 60 * time.Second
	// outputLimit bounds what is kept of a subcommand's output.
	outputLimit = 1 << 20
	// reasonLimit bounds the subcommand's error line a reason quotes.
	reasonLimit = 300
)

const (
	lockedText            = "The HyperDrop folder is locked or missing. Unlock it in Control Panel, Shared Folder."
	adminsText            = "HyperDrop could not read its administrators."
	notAdminSuffix        = " is not an administrator."
	seedText              = "HyperDrop could not write the new password down for the reset. Check free space on the volume."
	resetFailedText       = "HyperDrop could not reset the password"
	factorText            = "The password was reset, but the second factor was not removed"
	tooSlowText           = "it did not finish in 60 seconds."
	interruptedRescueText = "The reset was interrupted. Check the account and try again."
)

// The password refusals name the bounds the server holds every chosen
// password to.
var (
	tooShortText = fmt.Sprintf("A password needs at least %d characters.", metadb.MinPasswordBytes)
	tooLongText  = fmt.Sprintf("A password can be at most %d bytes long.", metadb.MaxPasswordBytes)
	commonText   = "This password is too common. Choose another."
)

// Admin is one administrator as GET /api/rescue lists it: its name and
// whether it can sign in ("active", "suspended" or "expired").
type Admin struct {
	Name     string `json:"name"`
	Standing string `json:"standing"`
}

// RescueRequest is the body of POST /api/rescue: an administrator, its new
// password and whether to remove its second factor too.
type RescueRequest struct {
	Account  string `json:"account"`
	Password string `json:"password"`
	Clear2FA bool   `json:"clear2fa"`
}

// rescueJob is the job file of an admin rescue.
type rescueJob struct {
	Job string `json:"job"`
	RescueRequest
}

func (p *page) seedPath() string { return p.varPath(".dsmpage-admin.seed") }

// rescueDir resolves the data folder the conf names.
func (p *page) rescueDir() (string, bool) {
	return p.dataDir(readConf(p.deps.ConfPath)["SHARED_FOLDER"])
}

// serveAdmins answers {"admins": [...]}, the volume's administrators.
func (p *page) serveAdmins(w http.ResponseWriter, r *http.Request, user string) {
	dir, ok := p.rescueDir()
	if !ok {
		writeError(w, http.StatusConflict, lockedText)
		return
	}
	admins, err := p.admins(dir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, adminsText)
		return
	}
	writeJSON(w, http.StatusOK, map[string][]Admin{"admins": admins})
}

// serveRescue checks the request and starts the worker that applies it.
func (p *page) serveRescue(w http.ResponseWriter, r *http.Request, user string) {
	if p.moveHeld(w) {
		return
	}
	var req RescueRequest
	if decodeBody(w, r, &req) != nil {
		writeError(w, http.StatusBadRequest, badRequestText)
		return
	}
	dir, ok := p.rescueDir()
	if !ok {
		writeError(w, http.StatusConflict, lockedText)
		return
	}
	if msg, code := p.rescueRefusal(req, dir); msg != "" {
		writeError(w, code, msg)
		return
	}
	p.startJob(w, rescueJobKind, rescueJob{Job: rescueJobKind, RescueRequest: req})
}

// accountRefusal answers why account cannot be reset on the volume in dir,
// and the status code for it, or "": it must be an administrator now, so a
// rescue never creates an account or resets a user's. An administrator who
// cannot sign in may still be reset.
func (p *page) accountRefusal(account, dir string) (string, int) {
	admins, err := p.admins(dir)
	if err != nil {
		return adminsText, http.StatusInternalServerError
	}
	if !slices.ContainsFunc(admins, func(a Admin) bool { return a.Name == account }) {
		return account + notAdminSuffix, http.StatusBadRequest
	}
	return "", 0
}

// rescueRefusal answers why req cannot run against the data folder dir, and
// the status code for it, or "": accountRefusal, then the rule the server
// holds every chosen password to.
func (p *page) rescueRefusal(req RescueRequest, dir string) (string, int) {
	if msg, code := p.accountRefusal(req.Account, dir); msg != "" {
		return msg, code
	}
	switch err := metadb.CheckChosenPassword(req.Password); {
	case errors.Is(err, metadb.ErrPasswordTooShort):
		return tooShortText, http.StatusBadRequest
	case errors.Is(err, metadb.ErrPasswordCommon):
		return commonText, http.StatusBadRequest
	case err != nil:
		return tooLongText, http.StatusBadRequest
	}
	return "", 0
}

// Rescue resets an administrator and answers the outcome, which it also
// records: it checks req against the volume before anything stops, stops
// the server, checks the account again, runs resetadmin and, when asked,
// reset2fa, then starts the server and waits for it as Save does. The
// server is started again whatever the reset did; a reset that failed is
// "failed" with its reason.
func (p *page) Rescue(req RescueRequest, svc Service, clk Clock) LastChange {
	failed := func(reason string) LastChange {
		return p.record(LastChange{State: "failed", Reason: reason, At: clk.Now().Unix(), Job: rescueJobKind})
	}
	dir, ok := p.rescueDir()
	if !ok {
		return failed(lockedText)
	}
	if msg, _ := p.rescueRefusal(req, dir); msg != "" {
		return failed(msg)
	}
	p.record(LastChange{State: "applying", At: clk.Now().Unix(), Job: rescueJobKind})

	if err := svc.Stop(); err != nil {
		svc.Start()
		return failed(notStoppedText)
	}
	resetReason := p.reset(dir, req)
	upReason, up := p.startAndWait(svc, clk)
	done := "Reset " + req.Account + "."
	switch {
	case resetReason != "":
		return failed(resetReason)
	case !up:
		return failed(done + " " + upReason)
	}
	return p.record(LastChange{State: "done", Reason: done, At: clk.Now().Unix(), Job: rescueJobKind})
}

// reset runs resetadmin with the password in its seed file and, when asked,
// reset2fa, against the data folder dir of a stopped server. It answers ""
// or why it failed. The account is checked once more first: the server
// changed the volume until it stopped, and resetadmin creates an
// administrator for a name it does not know.
func (p *page) reset(dir string, req RescueRequest) string {
	if msg, _ := p.accountRefusal(req.Account, dir); msg != "" {
		return msg
	}
	seed := p.seedPath()
	// resetadmin removes the seed once it has read it; one it never read
	// goes here.
	defer os.Remove(seed)
	if err := conffile.Write(seed, req.Password); err != nil {
		return seedText
	}
	if _, err := p.runServer(dir, []string{
		"HYPERDROP_ADMIN_USER=" + req.Account,
		"HYPERDROP_ADMIN_PASSWORD_FILE=" + seed,
	}, req.Password, "resetadmin"); err != nil {
		return resetFailedText + ": " + err.Error()
	}
	if req.Clear2FA {
		if _, err := p.runServer(dir, nil, req.Password, "reset2fa", req.Account); err != nil {
			return factorText + ": " + err.Error()
		}
	}
	return ""
}

// admins answers the administrators on the volume in dir, from the server
// binary's `admins --standing`, which reads the volume as it is and so runs
// beside a running server.
func (p *page) admins(dir string) ([]Admin, error) {
	out, err := p.runServer(dir, nil, "", "admins", "--standing")
	if err != nil {
		return nil, err
	}
	admins := []Admin{}
	for _, line := range strings.Split(out, "\n") {
		name, standing, _ := strings.Cut(strings.TrimSpace(line), "\t")
		if name != "" {
			admins = append(admins, Admin{Name: name, Standing: standing})
		}
	}
	return admins, nil
}

// runServer runs the server binary with args against the data folder dir
// and answers its output. Its environment is PATH, HYPERDROP_DATA and env,
// its standard input /dev/null, and it has subcommandLimit to finish. A
// failure's error is the first line of what it wrote to standard error,
// with every occurrence of secret hidden before the line is cut out.
func (p *page) runServer(dir string, env []string, secret string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), subcommandLimit)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.deps.ServerBinary, args...)
	cmd.Dir = "/"
	cmd.Env = append([]string{"PATH=" + scriptPATH, "HYPERDROP_DATA=" + dir}, env...)
	var stdout, stderr capped
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", errors.New(args[0] + ": " + tooSlowText)
		}
		if line := firstLine(hide(stderr.b, secret)); line != "" {
			return "", errors.New(line)
		}
		return "", errors.New(args[0] + ": " + err.Error())
	}
	return string(stdout.b), nil
}

// capped keeps the first outputLimit bytes written to it.
type capped struct{ b []byte }

func (c *capped) Write(b []byte) (int, error) {
	if room := outputLimit - len(c.b); room > 0 {
		c.b = append(c.b, b[:min(len(b), room)]...)
	}
	return len(b), nil
}

func (c *capped) String() string { return string(c.b) }

// firstLine answers the first non-blank line of b, trimmed and cut to
// reasonLimit bytes on a character boundary.
func firstLine(b []byte) string {
	for _, line := range bytes.Split(b, []byte("\n")) {
		s := strings.TrimSpace(strings.ToValidUTF8(string(line), "?"))
		if s == "" {
			continue
		}
		if len(s) > reasonLimit {
			cut := reasonLimit
			for cut > 0 && !utf8.RuneStart(s[cut]) {
				cut--
			}
			s = s[:cut] + "…"
		}
		return s
	}
	return ""
}

// hide replaces every occurrence of secret in b.
func hide(b []byte, secret string) []byte {
	if secret == "" {
		return b
	}
	return bytes.ReplaceAll(b, []byte(secret), []byte("[hidden]"))
}
