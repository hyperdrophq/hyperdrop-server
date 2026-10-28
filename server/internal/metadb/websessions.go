package metadb

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// A web session is a browser's sign-in: a row in tokens with kind 'web', so
// it is listed among the account's signed-in devices, revocable there, and
// revoked by a password change like any device. It is never a bearer token,
// on this server or on a release that knows nothing of it: its value has its
// own prefix and its row stores WebSessionHash, a domain-separated hash, so
// the bearer lookup (TokenHash, the plain SHA-256) never matches it, and
// UserByToken also refuses any row of kind 'web'. Only the cookie path
// computes the web hash.
//
// A public session ends WebIdle after its last use or WebAbsolute after its
// sign-in, whichever comes first; a kept one ends WebKeepFor after its last
// use. An expired row is deleted by the lookup that finds it, and by
// PruneWebSessions.

// WebTokenPrefix starts every web session's raw value.
const WebTokenPrefix = "hd_w_"

// TokenKindWeb is a web session's kind.
const TokenKindWeb = "web"

const (
	// WebIdle is how long a public session lives without a use.
	WebIdle = 30 * time.Minute
	// WebAbsolute is how long a public session lives at most.
	WebAbsolute = 12 * time.Hour
	// WebKeepFor is how long a kept session lives after its last use.
	WebKeepFor = 30 * 24 * time.Hour
	// webTouchEvery bounds how often a use moves a session's deadlines: a
	// lookup writes them only when they are at least this much behind.
	webTouchEvery = time.Minute
)

// WebSessionLimits are a session's idle and absolute limits.
func WebSessionLimits(keep bool) (idle, absolute time.Duration) {
	if keep {
		return WebKeepFor, WebKeepFor
	}
	return WebIdle, WebAbsolute
}

// WebSessionHash is what the database keeps of a web session's value.
func WebSessionHash(raw string) string {
	sum := sha256.Sum256([]byte("hyperdrop-web-session\n" + raw))
	return hex.EncodeToString(sum[:])
}

// mintWebSessionTx stores a new web session for name, signed in at
// signedIn and with its limits counted from now, and answers its raw value,
// the only moment it exists. Runs inside tx; the account's trim
// (trimTokens) counts it like any device.
func mintWebSessionTx(tx *sql.Tx, name, label string, keep bool, signedIn, now time.Time) (string, error) {
	idle, absolute := WebSessionLimits(keep)
	raw, id := WebTokenPrefix+randomHex(32), randomHex(8)
	if _, err := tx.Exec(`INSERT INTO tokens(id, username, sha256, label, created_at, kind, idle_until, expires_at, keep)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, name, WebSessionHash(raw), clampLabel(label), toNS(secs(signedIn)), TokenKindWeb,
		toNS(now.Add(idle)), toNS(now.Add(absolute)), keep); err != nil {
		return "", err
	}
	return raw, trimTokens(tx, name, []string{id})
}

// MintWebSession mints a web session for an existing account.
func (db *DB) MintWebSession(name, label string, keep bool, now time.Time) (raw string, err error) {
	err = db.write(func(tx *sql.Tx) error {
		if _, err := scanUser(tx, name); err != nil {
			return err
		}
		raw, err = mintWebSessionTx(tx, name, label, keep, now, now)
		return err
	})
	return
}

// MintWebSessionIfPasswordIs is MintTokenIfPasswordIs for a web session: the
// password hash and the second factor are checked in the transaction that
// mints it.
func (db *DB) MintWebSessionIfPasswordIs(name, label, passwordHash, code string, keep bool, now time.Time) (string, error) {
	return db.mintIfPasswordIs(name, passwordHash, code, now, func(tx *sql.Tx) (string, error) {
		return mintWebSessionTx(tx, name, label, keep, now, now)
	})
}

// MintWebSessionApprovedBy mints the public web session a phone approved
// for account name, answering the account and the session's raw value. The
// approving device token approverID must still be one of the account's
// device tokens and not one a phone signed in (ErrNoSuchToken otherwise:
// it was signed out, or the password changed, since the approval, or it
// may approve nothing, as MintDesktopSignIn refuses it) and the account
// active (ErrInactive), all read in the transaction that mints, which
// records the approver as the session's via_token.
func (db *DB) MintWebSessionApprovedBy(name, approverID, label string, now time.Time) (u User, raw string, err error) {
	err = db.write(func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRow(`SELECT count(*) FROM tokens WHERE id = ? AND username = ? AND kind IS NOT ?
			AND sign_in_method IS NOT ?`, approverID, name, TokenKindWeb, SignInMethodPhone).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return ErrNoSuchToken
		}
		if u, err = scanUser(tx, name); err != nil {
			return err
		}
		if !u.Active(now) {
			return ErrInactive
		}
		if raw, err = mintWebSessionTx(tx, name, label, false, now, now); err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE tokens SET via_token = ? WHERE sha256 = ?`, approverID, WebSessionHash(raw))
		return err
	})
	if err != nil {
		return User{}, "", err
	}
	return u, raw, nil
}

// SetPasswordMintingWebSession is SetPassword for a change made from a web
// session: every token and session of the account is revoked and a new web
// session with label and keep is minted for the browser, in one
// transaction, so the change never leaves the browser signed out. The new
// session keeps signedIn, the calling session's sign-in time, as a device's
// replacement token keeps its own (SetPasswordMintingToken), since the device
// list's age rule reads it.
func (db *DB) SetPasswordMintingWebSession(name, password, label string, keep bool, signedIn, now time.Time) (raw string, err error) {
	err = db.write(func(tx *sql.Tx) error {
		if err := setPassword(tx, name, password, true); err != nil {
			return err
		}
		raw, err = mintWebSessionTx(tx, name, label, keep, signedIn, now)
		return err
	})
	return
}

// UserByWebSession resolves a web session's raw value at now to its account
// and its own row. A session past its idle or absolute limit is deleted and
// answers ErrBadCredentials, like an unknown one. With touch (a request the
// user made, not a background poll) a use moves the idle limit, and a kept
// session's absolute limit with it, once they are webTouchEvery behind. The
// last-used stamp and the client header are kept as UserByToken keeps them.
// Every write is best-effort bookkeeping in one transaction.
func (db *DB) UserByWebSession(raw string, client ClientInfo, now time.Time, touch bool) (User, Token, error) {
	if !strings.HasPrefix(raw, WebTokenPrefix) {
		return User{}, Token{}, ErrBadCredentials
	}
	h := WebSessionHash(raw)
	var u User
	var idleUntil, expiresAt, lastUsed sql.NullInt64
	var keep bool
	var storedVersion string
	expired := false
	err := db.read(func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRow(`SELECT username, idle_until, expires_at, coalesce(keep, 0), last_used_at, client_version
			FROM tokens WHERE sha256 = ? AND kind = ?`, h, TokenKindWeb).
			Scan(&name, &idleUntil, &expiresAt, &keep, &lastUsed, &storedVersion); err != nil {
			return err
		}
		if !idleUntil.Valid || !expiresAt.Valid || !now.Before(fromNS(idleUntil.Int64)) || !now.Before(fromNS(expiresAt.Int64)) {
			expired = true
			return nil
		}
		var err error
		u, err = scanUser(tx, name)
		return err
	})
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrUserNotFound) {
		return User{}, Token{}, ErrBadCredentials
	}
	if err != nil {
		return User{}, Token{}, err
	}
	if expired {
		_ = db.write(func(tx *sql.Tx) error {
			_, err := tx.Exec(`DELETE FROM tokens WHERE sha256 = ? AND kind = ?`, h, TokenKindWeb)
			return err
		})
		return User{}, Token{}, ErrBadCredentials
	}
	if !u.Active(now) {
		return User{}, Token{}, ErrInactive
	}
	idle, _ := WebSessionLimits(keep)
	extend := touch && fromNS(idleUntil.Int64).Before(now.Add(idle-webTouchEvery))
	newIdle := now.Add(idle)
	use := useAt(now, lastUsed, storedVersion, client)
	if extend || use.due() {
		_ = db.write(func(tx *sql.Tx) error {
			if extend {
				q := `UPDATE tokens SET idle_until = ? WHERE sha256 = ?`
				if keep {
					q = `UPDATE tokens SET idle_until = ?1, expires_at = ?1 WHERE sha256 = ?2`
				}
				if _, err := tx.Exec(q, toNS(newIdle), h); err != nil {
					return err
				}
			}
			return use.record(tx, h)
		})
	}
	tok := patchToken(&u, h, func(t *Token) {
		if extend {
			t.IdleUntil = newIdle
			if keep {
				t.ExpiresAt, t.Slid = newIdle, true
			}
		}
		use.apply(t)
	})
	return u, tok, nil
}

// ElevateWebSession lets the account's web session tokenID make admin
// changes until until, answering ErrNoSuchToken when tokenID names none of
// the account's web sessions.
func (db *DB) ElevateWebSession(name, tokenID string, until time.Time) error {
	return db.write(func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE tokens SET elevated_until = ? WHERE username = ? AND id = ? AND kind = ?`,
			toNS(until), name, tokenID, TokenKindWeb)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNoSuchToken
		}
		return nil
	})
}

// EndWebSession deletes the web session whose value is raw, whatever its
// limits or its account's state say; a value that names none ends nothing.
func (db *DB) EndWebSession(raw string) error {
	if !strings.HasPrefix(raw, WebTokenPrefix) {
		return nil
	}
	_, err := db.deleteWebSessions(`sha256 = ? AND kind = ?`, WebSessionHash(raw), TokenKindWeb)
	return err
}

// RevokeWebSessions deletes every account's web sessions and answers how
// many, leaving every device token.
func (db *DB) RevokeWebSessions() (n int, err error) {
	return db.deleteWebSessions(`kind = ?`, TokenKindWeb)
}

// PruneWebSessions deletes the web sessions past their idle or absolute
// limit at now and answers how many.
func (db *DB) PruneWebSessions(now time.Time) (int, error) {
	return db.deleteWebSessions(`kind = ?1 AND (idle_until IS NULL OR idle_until <= ?2 OR expires_at IS NULL OR expires_at <= ?2)`,
		TokenKindWeb, toNS(now))
}

// deleteWebSessions deletes the token rows the condition where selects and
// answers how many.
func (db *DB) deleteWebSessions(where string, args ...any) (n int, err error) {
	err = db.write(func(tx *sql.Tx) error {
		res, err := tx.Exec(`DELETE FROM tokens WHERE `+where, args...)
		if err != nil {
			return err
		}
		c, err := res.RowsAffected()
		n = int(c)
		return err
	})
	return
}
