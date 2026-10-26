package metadb

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"hyperdrop/server/internal/totp"
)

const (
	recoveryCodeCount = 10
	recoveryCodeLen   = 10
	recoveryAlphabet  = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

// GenerateRecoveryCode returns a code like "AB2CD-EF3GH".
func GenerateRecoveryCode() string {
	b := make([]byte, recoveryCodeLen)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	out := make([]byte, 0, recoveryCodeLen+1)
	for i, v := range b {
		if i == recoveryCodeLen/2 {
			out = append(out, '-')
		}
		out = append(out, recoveryAlphabet[int(v)%len(recoveryAlphabet)])
	}
	return string(out)
}

// NormalizeRecoveryCode strips spaces and dashes and upper-cases, so a code
// typed with or without its dash matches.
func NormalizeRecoveryCode(code string) string {
	return strings.ToUpper(totp.Normalize(code))
}

func recoveryHash(code string) string {
	sum := sha256.Sum256([]byte(NormalizeRecoveryCode(code)))
	return hex.EncodeToString(sum[:])
}

// replaceRecoveryCodes mints a fresh set and stores their hashes. The raw
// codes exist once, in the return value.
func replaceRecoveryCodes(tx *sql.Tx, name string) ([]string, error) {
	if _, err := tx.Exec(`DELETE FROM recovery_codes WHERE username = ?`, name); err != nil {
		return nil, err
	}
	raw := make([]string, recoveryCodeCount)
	for i := range raw {
		raw[i] = GenerateRecoveryCode()
		if _, err := tx.Exec(`INSERT INTO recovery_codes(username, sha256) VALUES(?, ?)`, name, recoveryHash(raw[i])); err != nil {
			return nil, err
		}
	}
	return raw, nil
}

// StartTOTP begins an enrolment: it stores a fresh secret, sealed, and
// answers it in plaintext, the one place the plaintext leaves the server.
func (db *DB) StartTOTP(name string) (secret string, err error) {
	secret, err = totp.GenerateSecret()
	if err != nil {
		return "", err
	}
	sealed, err := sealTOTP(db.totpKey, name, secret)
	if err != nil {
		return "", err
	}
	err = db.write(func(tx *sql.Tx) error {
		u, err := scanUser(tx, name)
		if err != nil {
			return err
		}
		if u.TwoFactorEnabled() {
			return ErrTOTPAlreadyOn
		}
		_, err = tx.Exec(`UPDATE users SET totp_secret = ?, totp_confirmed_at = NULL, totp_last_step = 0 WHERE username = ?`, sealed, name)
		return err
	})
	if err != nil {
		return "", err
	}
	return secret, nil
}

func (db *DB) ConfirmTOTP(name, code string, now time.Time) (codes []string, err error) {
	err = db.write(func(tx *sql.Tx) error {
		u, err := scanUser(tx, name)
		if err != nil {
			return err
		}
		if u.TOTPStored == "" || u.TwoFactorEnabled() {
			return ErrTOTPNotPending
		}
		secret, opened, err := db.openStoredTOTP(&u)
		if err != nil {
			return err
		}
		if !opened {
			return ErrTOTPInvalid
		}
		step, ok := totp.Verify(secret, code, now, u.TOTPLastStep)
		if !ok {
			return ErrTOTPInvalid
		}
		if _, err := tx.Exec(`UPDATE users SET totp_confirmed_at = ?, totp_last_step = ? WHERE username = ?`, toNS(secs(now)), step, name); err != nil {
			return err
		}
		codes, err = replaceRecoveryCodes(tx, name)
		return err
	})
	return
}

// DisableTOTP turns the second factor off. Already off is not an error, so
// an operator reset never fails.
func (db *DB) DisableTOTP(name string) error {
	return db.write(func(tx *sql.Tx) error { return disableTOTP(tx, name, false) })
}

// ErrIsAdmin is DisableNonAdminTOTP meeting an administrator.
var ErrIsAdmin = errors.New("the account is an administrator")

// DisableNonAdminTOTP is DisableTOTP for an account the caller read as not
// an admin, refused with ErrIsAdmin when it is one by the time the write
// runs: clearing an admin's factor takes the caller's step-up, which a
// promotion landing between the read and the write must not skip.
func (db *DB) DisableNonAdminTOTP(name string) error {
	return db.write(func(tx *sql.Tx) error { return disableTOTP(tx, name, true) })
}

func disableTOTP(tx *sql.Tx, name string, refuseAdmin bool) error {
	u, err := scanUser(tx, name)
	if err != nil {
		return err
	}
	if refuseAdmin && u.IsAdmin() {
		return ErrIsAdmin
	}
	if _, err := tx.Exec(`UPDATE users SET totp_secret = NULL, totp_confirmed_at = NULL, totp_last_step = 0 WHERE username = ?`, name); err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM recovery_codes WHERE username = ?`, name)
	return err
}

func (db *DB) ResetRecoveryCodes(name string) (codes []string, err error) {
	err = db.write(func(tx *sql.Tx) error {
		u, err := scanUser(tx, name)
		if err != nil {
			return err
		}
		if !u.TwoFactorEnabled() {
			return ErrTOTPOff
		}
		codes, err = replaceRecoveryCodes(tx, name)
		return err
	})
	return
}

// checkSecondFactor accepts a TOTP code (advancing the spent step) or one
// unused recovery code (spending it). With 2FA off it accepts anything. A
// stored secret that does not open matches no TOTP code, and the recovery
// codes still answer.
func (db *DB) checkSecondFactor(tx *sql.Tx, u *User, code string, now time.Time) error {
	if !u.TwoFactorEnabled() {
		return nil
	}
	if code == "" {
		return ErrTOTPRequired
	}
	secret, opened, err := db.openStoredTOTP(u)
	if err != nil {
		return err
	}
	if opened {
		if step, ok := totp.Verify(secret, code, now, u.TOTPLastStep); ok {
			u.TOTPLastStep = step
			_, err := tx.Exec(`UPDATE users SET totp_last_step = ? WHERE username = ?`, step, u.Username)
			return err
		}
	}
	res, err := tx.Exec(`DELETE FROM recovery_codes WHERE username = ? AND sha256 = ?`, u.Username, recoveryHash(code))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		u.RecoveryCodesLeft--
		return nil
	}
	return ErrTOTPInvalid
}

func (db *DB) VerifySecondFactor(name, code string, now time.Time) error {
	return db.write(func(tx *sql.Tx) error {
		u, err := scanUser(tx, name)
		if err != nil {
			return err
		}
		return db.checkSecondFactor(tx, &u, code, now)
	})
}
