package api

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/updatesig"
)

const (
	// updateMaxBytes bounds the upload. The server binary is a few tens of MB
	// static; 256 MiB is far past any real build and still refuses a body meant
	// to fill the volume.
	updateMaxBytes = 256 << 20
	// stagedName is what the root-owned systemd path unit watches for.
	stagedName = "staged.bin"
	// stagedPartName is where the bytes land first. The installer must never
	// see a half-written binary, so the file only takes its watched name at the
	// atomic rename.
	stagedPartName = "staged.bin.part"
	// stagedSigName is the release signature beside it, written BEFORE the
	// binary takes its watched name, so the installer always finds the pair.
	stagedSigName = "staged.sig"
)

// stageError is a staging refusal with the status and code the update route
// answers; code "" answers a plain error.
type stageError struct {
	status    int
	code, msg string
}

func (e *stageError) Error() string { return e.msg }

// stage puts a release binary and its signature where the root installer
// watches: the bytes land in a part file, anything that is not a signed Linux
// executable for this host, no older than the version running, is refused,
// the database is backed up, the signature is written beside the binary, and
// the rename arms the installer. The backup follows the checks so a refused
// upload never rotates a good restore point out of backups/. The update route and the self-updater
// both stage through it, so both meet the same checks before the installed
// binary's own verify-update decides.
func (h *handler) stage(body io.Reader, sig []byte) (int64, error) {
	h.stageMu.Lock()
	defer h.stageMu.Unlock()
	return h.stageLocked(body, sig)
}

// stageLocked is stage with stageMu held.
func (h *handler) stageLocked(body io.Reader, sig []byte) (int64, error) {
	if err := os.MkdirAll(h.dep.UpdateDir, 0o700); err != nil {
		return 0, stagingFailed("creating the update directory", err)
	}
	part := filepath.Join(h.dep.UpdateDir, stagedPartName)
	f, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, stagingFailed("creating the staged binary", err)
	}
	n, copyErr := io.Copy(f, io.LimitReader(body, updateMaxBytes+1))
	closeErr := f.Close()
	switch {
	case copyErr != nil:
		// A cut upload leaves only the .part, which the installer never sees.
		os.Remove(part)
		return 0, &stageError{http.StatusBadRequest, "", "upload failed: " + copyErr.Error()}
	case closeErr != nil:
		os.Remove(part)
		return 0, stagingFailed("writing the staged binary", closeErr)
	case n > updateMaxBytes:
		os.Remove(part)
		return 0, &stageError{http.StatusRequestEntityTooLarge, "body-too-large", "that is larger than any real server build"}
	}
	if !looksLikeELF(part) {
		os.Remove(part)
		return 0, &stageError{http.StatusBadRequest, "not-a-server-binary", "that file is not a Linux executable"}
	}
	if err := verifyStaged(part, sig, h.version); err != nil {
		os.Remove(part)
		code := "bad-signature"
		if errors.Is(err, updatesig.ErrUnsigned) {
			code = "unsigned-binary"
		}
		return 0, &stageError{http.StatusBadRequest, code, err.Error()}
	}
	// A copy of the database before the binary changes: the restore point
	// for a damaged database. A rollback needs none, since the binary it
	// restarts serves every volume this one writes: a schema change at the
	// same stamp is one that binary ignores (metadb/additive.go).
	if h.dep.DataDir != "" {
		if _, err := metadb.Backup(h.db, filepath.Join(h.dep.DataDir, "backups"), time.Now()); err != nil {
			os.Remove(part)
			log.Printf("server update: backing up the database: %v", err)
			return 0, &stageError{http.StatusInternalServerError, "backup-failed",
				"the database could not be backed up before the update; the server log has the cause"}
		}
	}
	if err := writeStagedSig(h.dep.UpdateDir, sig); err != nil {
		os.Remove(part)
		return 0, stagingFailed("writing the staged signature", err)
	}
	// The rename is what arms the installer, and it is atomic, so the unit can
	// never observe a partial file.
	if err := os.Rename(part, filepath.Join(h.dep.UpdateDir, stagedName)); err != nil {
		os.Remove(part)
		return 0, stagingFailed("arming the installer", err)
	}
	return n, nil
}

// stagingFailed logs a filesystem failure while staging and answers a 500
// that names no path: the error's own text carries the data directory's
// layout, which is the log's business, not a client's.
func stagingFailed(step string, err error) error {
	log.Printf("server update: %s: %v", step, err)
	return &stageError{http.StatusInternalServerError, "", "the update could not be staged on the server; the server log has the cause"}
}

// stageRelease is stage for a binary already in memory: the self-updater's
// verified download, staged under the same lock as the route's.
func (h *handler) stageRelease(raw, sig []byte) error {
	h.stageMu.Lock()
	defer h.stageMu.Unlock()
	_, err := h.stageLocked(bytes.NewReader(raw), sig)
	return err
}

// elfMagic starts every Linux executable. Checked so an obvious mistake (an
// uploaded macOS build, a text file, a truncated download) is refused before it
// is ever staged. NOT a security boundary: an attacker who can reach this route
// can send a perfectly valid malicious ELF. The boundaries are the step-up
// auth below and, as root, the release signature the installer checks with
// the binary already installed (updatesig).
var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// updateServer accepts a replacement server binary and stages it for the
// root-owned installer unit to swap in.
//
// The server cannot install it itself and deliberately gains no privilege to:
// its unit runs as a non-root user under ProtectSystem=strict with only the
// data dir writable, so it can neither write /usr/local/bin nor call systemctl.
// It writes the file; a systemd path unit notices and a root oneshot does the
// swap, after which Restart=always brings this process back on the new binary.
//
// Authentication is STEP-UP, not the bearer token: this route grants root on the
// box, so it asks for what SSH would have asked for. A device token stolen from
// a Mac's Keychain must not be enough.
func (h *handler) updateServer(w http.ResponseWriter, r *http.Request) {
	u := reqUser(r)
	if h.dep.UpdateDir == "" {
		writeErrorCode(w, http.StatusNotImplemented, "update-unsupported",
			"this server's binary is managed outside HyperDrop (a container image or a package): update it the way it was installed")
		return
	}
	// The credentials ride headers rather than the body, because the body IS
	// the binary and the server must not buffer tens of megabytes before it
	// knows whether the caller may do this at all.
	password := r.Header.Get("X-HyperDrop-Password")
	code := r.Header.Get("X-HyperDrop-TOTP")

	// 2FA is REQUIRED here, whatever the account's own preference. This route
	// hands over root, so the one capability that must not rest on a single
	// factor is this one.
	if !u.TwoFactorEnabled() {
		writeErrorCode(w, http.StatusForbidden, "totp-setup-required",
			"set up two-factor authentication before updating the server over the network")
		return
	}
	if !h.requireCurrentPasswordAndCode(w, r, password, code) {
		return
	}
	// The client sends what the server's own /api/health reported, so a
	// mismatch means the wrong artifact was picked rather than a hostile one.
	if want := r.Header.Get("X-HyperDrop-Arch"); want != "" && want != runtime.GOARCH {
		writeErrorCode(w, http.StatusBadRequest, "arch-mismatch",
			"that build is for "+want+"; this server is "+runtime.GOARCH)
		return
	}

	// The signature is checked while staging so a refusal reaches the
	// caller; the root installer checks it again with the binary installed
	// on the box, which is the check that decides what runs as root.
	sig, err := base64.StdEncoding.DecodeString(r.Header.Get("X-HyperDrop-Signature"))
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, "bad-signature", "the signature header is not base64")
		return
	}
	n, err := h.stage(r.Body, sig)
	var refused *stageError
	switch {
	case errors.As(err, &refused) && refused.code == "":
		writeError(w, refused.status, refused.msg)
		return
	case errors.As(err, &refused):
		writeErrorCode(w, refused.status, refused.code, refused.msg)
		return
	case err != nil:
		writeRefusal(w, err)
		return
	}
	// 202: the swap, the restart and the health check all happen after this
	// response, and this process is about to be replaced. The client watches
	// /api/health for the version to change.
	writeJSON(w, http.StatusAccepted, map[string]any{
		"staged": true, "bytes": n, "startedAt": time.Now().UTC(),
	})
}

// verifyStaged checks the release signature of the binary at path, for this
// host's arch and no older than the version running.
func verifyStaged(path string, sig []byte, running string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = updatesig.Verify(updatesig.TrustedKeys, sig, f, runtime.GOARCH, running)
	return err
}

// writeStagedSig puts the signature at its staged name through a part file
// and a rename, so the installer never reads half of one.
func writeStagedSig(dir string, sig []byte) error {
	part := filepath.Join(dir, stagedSigName+".part")
	if err := os.WriteFile(part, sig, 0o600); err != nil {
		return err
	}
	if err := os.Rename(part, filepath.Join(dir, stagedSigName)); err != nil {
		os.Remove(part)
		return err
	}
	return nil
}

// looksLikeELF reports whether the staged file begins with the ELF magic.
func looksLikeELF(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var head [4]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		return false
	}
	return bytes.Equal(head[:], elfMagic)
}
