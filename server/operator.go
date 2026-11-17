package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"hyperdrop/server/dsmpage"
	"hyperdrop/server/internal/logfile"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/selfupdate"
	"hyperdrop/server/internal/systemfiles"
	"hyperdrop/server/internal/updatesig"
)

// runCheck opens the data volume as it is and runs the database's integrity
// check, for two subcommands. `checkschema` is the pre-flight the provisioner
// runs before replacing the running server, which is still serving the
// volume. `checkdb` is the same check for an operator who suspects the
// volume, and reportOK prints "ok" on success for it. cmd prefixes every
// error line. Exit codes:
//
//	0: this binary can serve the data
//	3: the data is newer than this binary knows (the client app is out of date)
//	1: the data directory could not be opened or failed the check
func runCheck(cmd, dataDir string, reportOK bool) int {
	db, err := metadb.OpenAsIs(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd, err)
		if errors.Is(err, metadb.ErrSchemaTooNew) {
			return 3
		}
		return 1
	}
	defer db.Close()
	if err := db.Check(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd, err)
		return 1
	}
	if reportOK {
		fmt.Println("ok")
	}
	return 0
}

// openVolume opens the data volume as is for the subcommand verb. On failure
// it prints the error and answers a nil database and the exit code.
func openVolume(verb, dataDir string) (*metadb.DB, int) {
	db, err := metadb.OpenAsIs(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", verb, err)
		return nil, 1
	}
	return db, 0
}

// openExistingVolume is openVolume for a read-only subcommand that never
// creates a database: with none in dataDir it answers a nil database and exit
// code 0, so a probe against a directory leaves nothing behind.
func openExistingVolume(verb, dataDir string) (*metadb.DB, int) {
	if _, err := os.Stat(filepath.Join(dataDir, metadb.FileName)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, 0
		}
		fmt.Fprintf(os.Stderr, "%s: %v\n", verb, err)
		return nil, 1
	}
	return openVolume(verb, dataDir)
}

// takeSeed reads the password seed file the environment variable env named
// for the subcommand verb and removes it, answering its bytes and exit code 0,
// or printing why not and answering the exit code. A seed that exists but
// cannot be read is removed too only with removeUnreadable.
func takeSeed(verb, env, seed string, removeUnreadable bool) ([]byte, int) {
	if seed == "" {
		fmt.Fprintf(os.Stderr, "%s: %s is not set\n", verb, env)
		return nil, 2
	}
	b, err := os.ReadFile(seed)
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "%s: no password seed at %s\n", verb, seed)
		return nil, 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", verb, err)
		if removeUnreadable {
			_ = os.Remove(seed)
		}
		return nil, 1
	}
	if err := os.Remove(seed); err != nil {
		fmt.Fprintf(os.Stderr, "%s: removing the password seed: %v\n", verb, err)
		return nil, 1
	}
	return b, 0
}

// runLogs prints the tail of the server's log file. The default and the
// cap match the admin route's, so the two readers show the same thing.
func runLogs(dataDir string, args []string) int {
	tail := logfile.DefaultTail
	for i := 0; i < len(args); i++ {
		if args[i] == "--tail" && i+1 < len(args) {
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 1 {
				fmt.Fprintf(os.Stderr, "logs: --tail wants a positive number, got %q\n", args[i+1])
				return 2
			}
			tail = min(n, logfile.MaxTail)
			i++
		}
	}
	out, err := logfile.Tail(filepath.Join(dataDir, "logs"), tail)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logs: %v\n", err)
		return 1
	}
	os.Stdout.Write(out)
	return 0
}

// runResetAdmin puts an administrator named by HYPERDROP_ADMIN_USER (empty:
// the sole existing admin, or the default name on an empty volume) on the
// volume with the password held in the seed file HYPERDROP_ADMIN_PASSWORD_FILE
// names, byte for byte. The file is removed once read, whatever the outcome,
// so the password neither sits on disk after the command nor ever passes
// through an environment or an argv another process could read. Every device
// token of that account is revoked with it: they were minted under the
// password being replaced.
func runResetAdmin(dataDir, name, seed string) int {
	b, exit := takeSeed("resetadmin", "HYPERDROP_ADMIN_PASSWORD_FILE", seed, false)
	if exit != 0 {
		return exit
	}
	password := string(b)
	if password == "" {
		fmt.Fprintf(os.Stderr, "resetadmin: the password seed %s is empty\n", seed)
		return 2
	}
	db, exit := openVolume("resetadmin", dataDir)
	if db == nil {
		return exit
	}
	defer db.Close()
	got, err := db.ResetAdmin(name, password)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resetadmin:", err)
		return 1
	}
	fmt.Printf("admin password reset for %s\n", got)
	return 0
}

// runAdmins powers the `admins` subcommand the provisioner, the installer's
// preflight and the app's arch probe run to learn whether a volume already
// holds an administrator: one username per line, nothing when there is no
// database yet. It never creates a database: a probe against a directory an
// install then abandons must leave nothing behind. With --standing each
// line is the name, a tab and whether the account can sign in: "active",
// "suspended" or "expired" (the DSM page's admin rescue labels the last two).
func runAdmins(dataDir string, args []string) int {
	withStanding := false
	switch {
	case len(args) == 0:
	case len(args) == 1 && args[0] == "--standing":
		withStanding = true
	default:
		fmt.Fprintln(os.Stderr, "admins: usage: hyperdrop-server admins [--standing]")
		return 2
	}
	db, exit := openExistingVolume("admins", dataDir)
	if db == nil {
		return exit
	}
	defer db.Close()
	names, err := db.AdminNames()
	if err != nil {
		fmt.Fprintf(os.Stderr, "admins: %v\n", err)
		return 1
	}
	now := time.Now()
	for _, n := range names {
		if !withStanding {
			fmt.Println(n)
			continue
		}
		u, err := db.User(n)
		if err != nil {
			fmt.Fprintf(os.Stderr, "admins: %v\n", err)
			return 1
		}
		fmt.Printf("%s\t%s\n", n, standing(u, now))
	}
	return 0
}

// standing is whether an account can sign in, as the operator subcommands
// print it: "active", "suspended" or "expired".
func standing(u metadb.User, now time.Time) string {
	switch {
	case u.Disabled:
		return "suspended"
	case !u.Active(now):
		return "expired"
	}
	return "active"
}

// runAccounts powers the `accounts` subcommand Server Management's account
// rescue runs over SSH: one line per account, sorted by name, holding the
// name, the role, the standing (standing) and whether a second factor is on
// ("on" or "off"), separated by tabs. Like `admins` it never creates a
// database and only reads one, so it runs beside a serving process.
func runAccounts(dataDir string, args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "accounts: usage: hyperdrop-server accounts")
		return 2
	}
	db, exit := openExistingVolume("accounts", dataDir)
	if db == nil {
		return exit
	}
	defer db.Close()
	users, err := db.Users()
	if err != nil {
		fmt.Fprintf(os.Stderr, "accounts: %v\n", err)
		return 1
	}
	now := time.Now()
	for _, u := range users {
		twoFactor := "off"
		if u.TwoFactorEnabled() {
			twoFactor = "on"
		}
		fmt.Printf("%s\t%s\t%s\t%s\n", u.Username, u.Role, standing(u, now), twoFactor)
	}
	return 0
}

// passwordRefusalCode is the code `setpassword` prints for a password
// metadb.CheckChosenPassword refuses, the API's code for the same rule.
func passwordRefusalCode(err error) string {
	switch {
	case errors.Is(err, metadb.ErrPasswordTooShort):
		return "password-too-short"
	case errors.Is(err, metadb.ErrPasswordTooLong):
		return "password-too-long"
	}
	return "password-common"
}

// runSetPassword powers `setpassword <account>`: it sets an existing
// account's password from the seed file HYPERDROP_PASSWORD_FILE names and
// removes the file once read, whatever the outcome, so the password never
// passes through an argv or an environment. It never creates an account
// (exit 4 for a name the volume does not hold) and refuses a password the
// server's own rule refuses (exit 5, the code on stderr). Every device token
// and live device link of the account is revoked with the change, as a
// password change through the API does. It prints SETPASSWORD-DONE.
func runSetPassword(dataDir string, args []string, seed string) int {
	b, exit := takeSeed("setpassword", "HYPERDROP_PASSWORD_FILE", seed, true)
	if exit != 0 {
		return exit
	}
	if len(args) != 1 || !metadb.ValidUsername(args[0]) {
		fmt.Fprintln(os.Stderr, "setpassword: usage: HYPERDROP_PASSWORD_FILE=<seed> hyperdrop-server setpassword <account>")
		return 2
	}
	account, password := args[0], string(b)
	if err := metadb.CheckChosenPassword(password); err != nil {
		fmt.Fprintf(os.Stderr, "setpassword: %s: %v\n", passwordRefusalCode(err), err)
		return 5
	}
	if _, err := os.Stat(filepath.Join(dataDir, metadb.FileName)); err != nil {
		fmt.Fprintf(os.Stderr, "setpassword: no HyperDrop database in %s: %v\n", dataDir, err)
		return 1
	}
	db, exit := openVolume("setpassword", dataDir)
	if db == nil {
		return exit
	}
	defer db.Close()
	switch err := db.SetPassword(account, password); {
	case errors.Is(err, metadb.ErrUserNotFound):
		fmt.Fprintf(os.Stderr, "setpassword: no account %s\n", account)
		return 4
	case err != nil:
		fmt.Fprintf(os.Stderr, "setpassword: %v\n", err)
		return 1
	}
	fmt.Println("SETPASSWORD-DONE")
	return 0
}

// notOfficialUpdates is why a build that is not official never installs a
// release on its own, as the API's self-update-unavailable says it.
const notOfficialUpdates = "this server is not an official HyperDrop build, so it does not install updates on its own"

// runAutoUpdate powers `auto-update [on|off]`. It never creates a database:
// a volume that does not exist yet has no switch to read or turn. A build
// that is not official prints "unavailable: <why>" after the switch and
// refuses to turn it (exit 3).
func runAutoUpdate(dataDir string, args []string) int {
	on, set := false, len(args) == 1
	switch {
	case len(args) == 0:
	case set && args[0] == "on":
		on = true
	case set && args[0] == "off":
	default:
		fmt.Fprintln(os.Stderr, "auto-update: usage: hyperdrop-server auto-update [on|off]")
		return 2
	}
	if set && official != "true" {
		fmt.Fprintln(os.Stderr, "auto-update:", notOfficialUpdates)
		return 3
	}
	if _, err := os.Stat(filepath.Join(dataDir, metadb.FileName)); err != nil {
		fmt.Fprintf(os.Stderr, "auto-update: no HyperDrop database in %s: %v\n", dataDir, err)
		return 1
	}
	db, exit := openVolume("auto-update", dataDir)
	if db == nil {
		return exit
	}
	defer db.Close()
	if set {
		if err := selfupdate.Switch(db, on); err != nil {
			fmt.Fprintf(os.Stderr, "auto-update: %v\n", err)
			return 1
		}
	}
	on, err := selfupdate.AutoIn(db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "auto-update: %v\n", err)
		return 1
	}
	if on {
		fmt.Println("on")
	} else {
		fmt.Println("off")
	}
	if official != "true" {
		fmt.Println("unavailable:", notOfficialUpdates)
	}
	return 0
}

// runReset2FA powers `reset2fa <account>`: it clears the account's second
// factor and recovery codes. The client runs it over SSH with the unit
// stopped, so no login is mid-flight while the factor goes away; the stdout
// markers are what the client reads. An unfinished enrolment is cleared with
// a confirmed one: only an account with no secret at all is already off.
func runReset2FA(dataDir, account string) int {
	if !metadb.ValidUsername(account) {
		fmt.Fprintln(os.Stderr, "reset2fa: usage: hyperdrop-server reset2fa <account>")
		return 2
	}
	db, exit := openVolume("reset2fa", dataDir)
	if db == nil {
		return exit
	}
	defer db.Close()
	u, err := db.User(account)
	if errors.Is(err, metadb.ErrUserNotFound) {
		fmt.Fprintf(os.Stderr, "reset2fa: no account %s\n", account)
		return 4
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "reset2fa: %v\n", err)
		return 1
	}
	if !u.TwoFactorEnabled() && u.TOTPStored == "" {
		fmt.Println("RESET2FA-ALREADY-OFF")
		return 0
	}
	if err := db.DisableTOTP(account); err != nil {
		fmt.Fprintf(os.Stderr, "reset2fa: %v\n", err)
		return 1
	}
	fmt.Println("RESET2FA-DONE")
	return 0
}

// operatorCommand runs the subcommand args names (os.Args without the
// program) and answers its exit code. The operator subcommands each run
// against the data volume and exit without serving; dsmpage and
// dsmpage-apply are the Synology package page's CGI and its worker. With no
// argument it answers serve true: the process starts a server. An argument
// it does not know exits 2 rather than serving, so a caller that asks for a
// subcommand a binary lacks never opens the volume in serving mode.
func operatorCommand(dataDir string, args []string) (exit int, serve bool) {
	if len(args) == 0 {
		return 0, true
	}
	rest := args[1:]
	switch args[0] {
	case "checkschema":
		// A read-only pre-flight the provisioner runs against the data
		// volume BEFORE replacing the running container, so a downgrade
		// is refused while the old server is still serving.
		return runCheck("checkschema", dataDir, false), false
	case "resetadmin":
		// Sets the admin account's password from the seed file
		// HYPERDROP_ADMIN_PASSWORD_FILE names, and removes the file.
		//
		// The recovery path for a data volume that outlived the password
		// that created it: EnsureAdmin only seeds on a FIRST boot, so
		// re-provisioning a volume that already has an admin cannot
		// change it, and the install then succeeds while the login that
		// follows bounces. Whoever runs this already has root on the box
		// over SSH, which is strictly more authority than the admin
		// account it resets, so it grants nothing new. It deliberately
		// keeps every share: only the password changes.
		return runResetAdmin(dataDir, os.Getenv("HYPERDROP_ADMIN_USER"), os.Getenv("HYPERDROP_ADMIN_PASSWORD_FILE")), false
	case "admins":
		// Prints the username of every administrator on the data volume,
		// one per line. The provisioner, the installer's preflight and
		// the app's arch probe read it to learn whether the volume
		// already holds an administrator; empty output means it does not.
		// --standing adds whether each one can sign in.
		return runAdmins(dataDir, rest), false
	case "reset2fa":
		// reset2fa <account>: clears one account's second factor and
		// recovery codes, for an operator who lost the authenticator that
		// holds the only way into their own server. The client runs it
		// over SSH with the unit stopped.
		account := ""
		if len(rest) > 0 {
			account = rest[0]
		}
		return runReset2FA(dataDir, account), false
	case "accounts":
		// Prints every account on the data volume, one per line: name,
		// role, standing and two-factor, tab-separated. Server
		// Management's account rescue reads it over SSH beside the
		// running server.
		return runAccounts(dataDir, rest), false
	case "setpassword":
		// setpassword <account>: sets an existing account's password from
		// the seed file HYPERDROP_PASSWORD_FILE names, and removes the
		// file. Server Management's account rescue runs it over SSH with
		// the unit stopped. Whoever runs it already holds the box, which
		// is more than any administrator.
		return runSetPassword(dataDir, rest, os.Getenv("HYPERDROP_PASSWORD_FILE")), false
	case "auto-update":
		// auto-update [on|off]: prints "on" or "off", or turns automatic
		// updates on or off on the data volume, as an admin's switch in
		// the apps does; a build that is not official says so on a second
		// line and refuses the switch, as the API does. Server Management runs it over SSH as the
		// service account, beside the running server, then sends that
		// server SIGUSR1 so a switch turned on checks at once. Whoever
		// runs it already holds the box, which is more than any admin.
		return runAutoUpdate(dataDir, rest), false
	case "checkdb":
		// An integrity check of the data volume's database, printed.
		return runCheck("checkdb", dataDir, true), false
	case "logs":
		// logs [--tail N]: the last N lines (default 2000) of the server's
		// own log, across its rotated files. Server Management runs it over
		// SSH, which is how a box whose service is down still shows what
		// it did last.
		return runLogs(dataDir, rest), false
	case "verify-update":
		// verify-update <binary> <signature>: exits 0 only when the
		// signature is a release key's, names this binary's bytes and
		// this host's arch, and is not older than this version. The root
		// installer runs it with the binary ALREADY installed before it
		// executes anything staged, which is what makes the release key,
		// not whoever can write the staging directory, decide what runs
		// as root.
		return runVerifyUpdate(rest), false
	case "system-files":
		// Prints the provisioner this binary embeds and exits, touching
		// nothing. The root updater runs it with the binary it has just
		// verified, as root, and renders the service unit, itself and
		// its units from what it prints, so a normal update refreshes
		// what the install wrote.
		return systemfiles.Run(os.Stdout), false
	case "dsmpage":
		// The CGI behind the package's page in DSM's main menu
		// (ui/index.cgi execs it once per request). It never opens the
		// data volume, so it answers while the server is stopped.
		return dsmpage.Serve(), false
	case "dsmpage-apply":
		// dsmpage-apply <job>: the DSM page's Save, which the CGI starts
		// in a session of its own because stopping, starting and
		// watching the server outlasts the request.
		return dsmpage.RunApply(rest), false
	case "version", "--version", "-version":
		// The over-the-air update installer runs this against a STAGED
		// binary before it replaces a working one, so "does this file
		// actually execute on this host" is answered without side
		// effects and without binding a port. A client that runs another
		// subcommand over SSH asks it first: a binary older than the
		// subcommand starts a server on an argument it does not know.
		fmt.Println(version)
		return 0, false
	}
	fmt.Fprintf(os.Stderr, "hyperdrop-server: unknown command %q\n", args[0])
	return 2, false
}

// runVerifyUpdate is the verify-update subcommand.
func runVerifyUpdate(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: hyperdrop-server verify-update <binary> <signature>")
		return 2
	}
	sig, err := readSignature(args[1])
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(os.Stderr, "verify-update:", err)
		return 1
	}
	bin, err := os.Open(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-update:", err)
		return 1
	}
	defer bin.Close()
	st, err := updatesig.Verify(updatesig.TrustedKeys, sig, bin, runtime.GOARCH, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-update:", err)
		return 1
	}
	fmt.Println("verified", st.Version, st.Arch)
	return 0
}

// readSignature reads a signature file, at most one byte past
// updatesig.MaxSize: a longer file is refused by Verify, so nothing past that
// is worth reading, however large the staged file is.
func readSignature(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, updatesig.MaxSize+1))
}
