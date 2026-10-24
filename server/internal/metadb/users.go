package metadb

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"hyperdrop/server/internal/shareid"
)

// Token is one device's bearer credential. The raw token is never stored,
// only its SHA-256.
type Token struct {
	ID             string
	SHA256         string
	Label          string
	CreatedAt      time.Time
	LastUsedAt     time.Time // zero when never used
	ClientVersion  string
	ClientPlatform string
	ViaToken       string // the id of the token that approved this one; "" when none or gone
}

// User is one account and everything it owns except its shares.
type User struct {
	Username          string
	PasswordHash      string
	Role              string
	CreatedAt         time.Time
	Disabled          bool
	AccountExpiresAt  *time.Time
	QuotaBytes        int64
	NoEmbed           bool
	SourceRoots       []string
	Tokens            []Token
	TOTPStored        string     // the secret as the row holds it, sealed (totpseal.go); "" = off
	TOTPConfirmedAt   *time.Time // nil while enrolment is unfinished
	TOTPLastStep      int64
	RecoveryCodesLeft int
}

func (u User) IsAdmin() bool          { return u.Role == RoleAdmin }
func (u User) TwoFactorEnabled() bool { return u.TOTPStored != "" && u.TOTPConfirmedAt != nil }
func (u User) Active(now time.Time) bool {
	return !u.Disabled && (u.AccountExpiresAt == nil || now.Before(*u.AccountExpiresAt))
}

// Settings carries the fields an update may change. A pointer field is
// applied; nil leaves that setting alone.
type Settings struct {
	QuotaBytes         *int64
	NoEmbed, Disabled  *bool
	AccountExpiresAt   *time.Time
	ClearAccountExpiry bool
	SourceRoots        *[]string
	Role               *string
	// Password sets a new password, which signs out every device and clears
	// the account's invite (setPassword), in the transaction that applies
	// the rest, so an edit that cannot set it changes nothing.
	Password *string
}

var nameRe = regexp.MustCompile(`^[a-z0-9._-]{3,32}$`)

func ValidUsername(name string) bool { return nameRe.MatchString(name) }
func ValidRole(role string) bool     { return role == RoleAdmin || role == RoleUser }

// MinPasswordBytes and MaxPasswordBytes bound a password a person chooses
// (a new account's, an admin setting one, a password change, the DSM page's
// admin rescue). bcrypt reads at most 72 bytes and refuses more. A password
// already set is never measured: an account whose password predates the
// rule signs in as before.
const (
	MinPasswordBytes = 8
	MaxPasswordBytes = 72
)

var (
	ErrPasswordTooShort = fmt.Errorf("a password needs at least %d characters", MinPasswordBytes)
	ErrPasswordTooLong  = fmt.Errorf("a password can be at most %d bytes long", MaxPasswordBytes)
)

// CheckChosenPassword refuses a chosen password outside the bounds.
func CheckChosenPassword(pw string) error {
	switch {
	case len(pw) < MinPasswordBytes:
		return ErrPasswordTooShort
	case len(pw) > MaxPasswordBytes:
		return ErrPasswordTooLong
	}
	return nil
}

// GeneratePassword returns 16 random base58 characters.
func GeneratePassword() string { return shareid.RandomBase58(16) }

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// TokenHash is what the database keeps of a bearer token.
func TokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

const userCols = `username, password_hash, role, created_at, disabled, account_expires_at,
	quota_bytes, no_embed, totp_secret, totp_confirmed_at, totp_last_step`

// tokensOf is the rest of scanUser's token query, after the columns.
const tokensOf = ` FROM tokens WHERE username = ? ORDER BY created_at, id` // #nosec G101 -- a SQL fragment naming the tokens table

// scanUser reads one users row and its child rows. Runs inside the caller's tx.
func scanUser(tx *sql.Tx, name string) (User, error) {
	var u User
	var created int64
	var expires, confirmed sql.NullInt64
	var secret sql.NullString
	err := tx.QueryRow(`SELECT `+userCols+` FROM users WHERE username = ?`, name).Scan(
		&u.Username, &u.PasswordHash, &u.Role, &created, &u.Disabled, &expires,
		&u.QuotaBytes, &u.NoEmbed, &secret, &confirmed, &u.TOTPLastStep)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.CreatedAt = fromNS(created)
	u.AccountExpiresAt = fromNSPtr(expires)
	u.TOTPStored = secret.String
	u.TOTPConfirmedAt = fromNSPtr(confirmed)
	rows, err := tx.Query(`SELECT root FROM user_source_roots WHERE username = ? ORDER BY root`, name)
	if err != nil {
		return User{}, err
	}
	if u.SourceRoots, err = scanStrings(rows); err != nil {
		return User{}, err
	}
	rows, err = tx.Query(`SELECT id, sha256, label, created_at, last_used_at, client_version, client_platform, via_token`+tokensOf, name)
	if err != nil && strings.Contains(err.Error(), "no such column: via_token") {
		// A volume opened as is may predate via_token, which only the
		// serving open adds; its tokens then have no approver. The serving
		// path never meets this, so it pays for no schema probe.
		rows, err = tx.Query(`SELECT id, sha256, label, created_at, last_used_at, client_version, client_platform, NULL`+tokensOf, name)
	}
	if err != nil {
		return User{}, err
	}
	err = eachRow(rows, func() error {
		var tok Token
		var c int64
		var lu sql.NullInt64
		var via sql.NullString
		if err := rows.Scan(&tok.ID, &tok.SHA256, &tok.Label, &c, &lu, &tok.ClientVersion, &tok.ClientPlatform, &via); err != nil {
			return err
		}
		tok.ViaToken = via.String
		tok.CreatedAt = fromNS(c)
		if lu.Valid {
			tok.LastUsedAt = fromNS(lu.Int64)
		}
		u.Tokens = append(u.Tokens, tok)
		return nil
	})
	if err != nil {
		return User{}, err
	}
	if err := tx.QueryRow(`SELECT count(*) FROM recovery_codes WHERE username = ?`, name).Scan(&u.RecoveryCodesLeft); err != nil {
		return User{}, err
	}
	return u, nil
}

// ErrLastAdmin is an edit or a delete that would leave the server with no
// admin able to sign in, or that takes away the last admin whose access has
// no end date.
var ErrLastAdmin = errors.New("this would leave the server without an active administrator")

// adminStanding counts the admins other than except that are active at now
// and, of those, the ones whose access never expires.
func adminStanding(tx *sql.Tx, now time.Time, except string) (c adminCount, err error) {
	err = tx.QueryRow(`SELECT count(*), coalesce(sum(account_expires_at IS NULL), 0) FROM users
		WHERE role = ? AND disabled = 0 AND (account_expires_at IS NULL OR account_expires_at > ?) AND username <> ?`,
		RoleAdmin, toNS(now), except).Scan(&c.active, &c.lasting)
	return
}

// adminCount is adminStanding's answer: the active admins, and how many of
// them never expire.
type adminCount struct{ active, lasting int }

// leftWithoutAdmin is the verdict on an account change: it took away the
// last active admin, or the last admin that never expires. A change that
// moves neither count to zero is allowed, so an edit on a volume that
// already holds no such admin is not blocked by it.
func leftWithoutAdmin(before, after adminCount) error {
	if (after.active == 0 && before.active > 0) || (after.lasting == 0 && before.lasting > 0) {
		return ErrLastAdmin
	}
	return nil
}

// keepsAnAdmin runs change inside tx and refuses it with ErrLastAdmin when it
// takes the server's last admin away (leftWithoutAdmin): two admins expiring
// each other, or demoting, suspending or deleting each other at once, each
// pass the rule that keeps an admin from locking themselves out, and the
// server would be left with no admin to undo it.
func keepsAnAdmin(tx *sql.Tx, change func() error) error {
	now := time.Now()
	before, err := adminStanding(tx, now, "")
	if err != nil {
		return err
	}
	if err := change(); err != nil {
		return err
	}
	after, err := adminStanding(tx, now, "")
	if err != nil {
		return err
	}
	return leftWithoutAdmin(before, after)
}

// applySettings writes the pointer fields of s onto an existing account's
// row, refused with ErrLastAdmin when the edit would leave the server
// without an admin (keepsAnAdmin). Runs inside tx.
func applySettings(tx *sql.Tx, name string, s Settings) error {
	if s.Role == nil && s.Disabled == nil && s.AccountExpiresAt == nil {
		return writeSettings(tx, name, s)
	}
	return keepsAnAdmin(tx, func() error { return writeSettings(tx, name, s) })
}

// writeSettings writes the pointer fields of s onto the row. Runs inside tx.
func writeSettings(tx *sql.Tx, name string, s Settings) error {
	set := func(col string, v any) error {
		_, err := tx.Exec(`UPDATE users SET `+col+` = ? WHERE username = ?`, v, name)
		return err
	}
	if s.Role != nil {
		if !ValidRole(*s.Role) {
			return fmt.Errorf("%w: role %q", ErrBadRequest, *s.Role)
		}
		if err := set("role", *s.Role); err != nil {
			return err
		}
	}
	if s.QuotaBytes != nil {
		if err := set("quota_bytes", *s.QuotaBytes); err != nil {
			return err
		}
	}
	if s.NoEmbed != nil {
		if err := set("no_embed", *s.NoEmbed); err != nil {
			return err
		}
	}
	if s.Disabled != nil {
		if err := set("disabled", *s.Disabled); err != nil {
			return err
		}
	}
	if s.AccountExpiresAt != nil {
		if err := set("account_expires_at", toNS(secs(*s.AccountExpiresAt))); err != nil {
			return err
		}
	}
	if s.ClearAccountExpiry {
		if err := set("account_expires_at", nil); err != nil {
			return err
		}
	}
	if s.SourceRoots != nil {
		if _, err := tx.Exec(`DELETE FROM user_source_roots WHERE username = ?`, name); err != nil {
			return err
		}
		for _, r := range *s.SourceRoots {
			if _, err := tx.Exec(`INSERT OR IGNORE INTO user_source_roots(username, root) VALUES(?, ?)`, name, r); err != nil {
				return err
			}
		}
	}
	if s.Password != nil {
		return setPassword(tx, name, *s.Password, true)
	}
	return nil
}

func createUser(tx *sql.Tx, name, password, role string, s Settings) (User, error) {
	if !ValidUsername(name) {
		return User{}, fmt.Errorf("%w (got %q)", ErrBadName, name)
	}
	if !ValidRole(role) {
		return User{}, fmt.Errorf("%w: role %q", ErrBadRequest, role)
	}
	if _, err := scanUser(tx, name); err == nil {
		return User{}, fmt.Errorf("%w: %s", ErrExists, name)
	} else if !errors.Is(err, ErrUserNotFound) {
		return User{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return User{}, err
	}
	if _, err := tx.Exec(`INSERT INTO users(username, password_hash, role, created_at) VALUES(?, ?, ?, ?)`,
		name, string(hash), role, toNS(secs(time.Now()))); err != nil {
		return User{}, err
	}
	if err := writeSettings(tx, name, s); err != nil {
		return User{}, err
	}
	return scanUser(tx, name)
}

func (db *DB) CreateUser(name, password, role string, s Settings) (u User, err error) {
	err = db.write(func(tx *sql.Tx) error { u, err = createUser(tx, name, password, role, s); return err })
	return
}

func (db *DB) User(name string) (u User, err error) {
	err = db.read(func(tx *sql.Tx) error { u, err = scanUser(tx, name); return err })
	return
}

func (db *DB) Users() (out []User, err error) {
	err = db.read(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT username FROM users ORDER BY username`)
		if err != nil {
			return err
		}
		names, err := scanStrings(rows)
		if err != nil {
			return err
		}
		for _, n := range names {
			u, err := scanUser(tx, n)
			if err != nil {
				return err
			}
			out = append(out, u)
		}
		return nil
	})
	return
}

func (db *DB) UpdateUser(name string, s Settings) (User, error) {
	return db.UpdateUserAccess(name, s, nil)
}

// DeleteUser removes an account and its tokens, roots and recovery codes.
// An account that still owns shares answers ErrConflict: the caller deletes
// the shares first, so an account can never vanish under its content. The
// last admin answers ErrLastAdmin (keepsAnAdmin).
func (db *DB) DeleteUser(name string) error {
	return db.write(func(tx *sql.Tx) error {
		if _, err := scanUser(tx, name); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(`SELECT count(*) FROM shares WHERE owner = ?`, name).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%w: %s still owns %d share(s)", ErrConflict, name, n)
		}
		return keepsAnAdmin(tx, func() error {
			_, err := tx.Exec(`DELETE FROM users WHERE username = ?`, name)
			return err
		})
	})
}

// DeleteKeepsAnAdmin answers ErrLastAdmin when deleting name would leave the
// server without an admin, the question a caller asks before it removes
// anything the account owns. DeleteUser asks it again in its own write.
func (db *DB) DeleteKeepsAnAdmin(name string) error {
	return db.read(func(tx *sql.Tx) error {
		now := time.Now()
		before, err := adminStanding(tx, now, "")
		if err != nil {
			return err
		}
		after, err := adminStanding(tx, now, name)
		if err != nil {
			return err
		}
		return leftWithoutAdmin(before, after)
	})
}

func adminNames(tx *sql.Tx) ([]string, error) {
	rows, err := tx.Query(`SELECT username FROM users WHERE role = ? ORDER BY username`, RoleAdmin)
	if err != nil {
		return nil, err
	}
	return scanStrings(rows)
}

func (db *DB) AdminNames() (out []string, err error) {
	err = db.read(func(tx *sql.Tx) error { out, err = adminNames(tx); return err })
	return
}

// EnsureAdmin creates the first administrator on a volume that has none.
// Once any admin exists it does nothing, whatever the arguments.
func (db *DB) EnsureAdmin(name, password string) error {
	return db.write(func(tx *sql.Tx) error {
		admins, err := adminNames(tx)
		if err != nil {
			return err
		}
		if len(admins) > 0 {
			return nil
		}
		if name == "" {
			name = DefaultAdminName
		}
		if !ValidUsername(name) {
			return fmt.Errorf("HYPERDROP_ADMIN_USER: %w (got %q)", ErrBadName, name)
		}
		if password == "" {
			return errors.New("no admin account exists and HYPERDROP_ADMIN_PASSWORD is not set")
		}
		_, err = createUser(tx, name, password, RoleAdmin, Settings{})
		return err
	})
}

// ResetAdmin sets an admin's password, revoking its tokens, or creates the
// admin when the name is new. With no name it picks the only admin, or the
// default name on an empty volume, and refuses to guess between several.
func (db *DB) ResetAdmin(name, password string) (chosen string, err error) {
	if password == "" {
		return "", errors.New("HYPERDROP_ADMIN_PASSWORD is not set")
	}
	err = db.write(func(tx *sql.Tx) error {
		admins, err := adminNames(tx)
		if err != nil {
			return err
		}
		if name == "" {
			switch len(admins) {
			case 0:
				name = DefaultAdminName
			case 1:
				name = admins[0]
			default:
				return fmt.Errorf("several admin accounts exist (%s); set HYPERDROP_ADMIN_USER to the one to reset",
					strings.Join(admins, ", "))
			}
		}
		if !ValidUsername(name) {
			return fmt.Errorf("HYPERDROP_ADMIN_USER: %w (got %q)", ErrBadName, name)
		}
		u, err := scanUser(tx, name)
		if errors.Is(err, ErrUserNotFound) {
			_, err = createUser(tx, name, password, RoleAdmin, Settings{})
			chosen = name
			return err
		}
		if err != nil {
			return err
		}
		if !u.IsAdmin() {
			return fmt.Errorf("%s is not an admin account; set HYPERDROP_ADMIN_USER to an admin or a new name", name)
		}
		chosen = name
		return setPassword(tx, name, password, true)
	})
	return
}

func setPassword(tx *sql.Tx, name, password string, revokeTokens bool) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE users SET password_hash = ? WHERE username = ?`, string(hash), name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	if revokeTokens {
		if _, err = tx.Exec(`DELETE FROM tokens WHERE username = ?`, name); err != nil {
			return err
		}
	}
	return clearInvite(tx, name)
}

var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("hyperdrop-timing-dummy"), BcryptCost)

// Authenticate checks a password. An unknown name still costs one bcrypt
// compare so timing does not reveal which names exist. Only a wrong password
// or an unknown name is ErrBadCredentials: a database that cannot be read
// answers its own error, so a fault is never counted or shown as a guess.
func (db *DB) Authenticate(name, password string) (User, error) {
	u, err := db.User(name)
	if errors.Is(err, ErrUserNotFound) {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return User{}, ErrBadCredentials
	}
	if err != nil {
		return User{}, err
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return User{}, ErrBadCredentials
	}
	if !u.Active(time.Now()) {
		return User{}, ErrInactive
	}
	return u, nil
}

func (db *DB) SetPassword(name, password string) error {
	return db.write(func(tx *sql.Tx) error { return setPassword(tx, name, password, true) })
}

func (db *DB) SetPasswordKeepingTokens(name, password string) error {
	return db.write(func(tx *sql.Tx) error { return setPassword(tx, name, password, false) })
}

// MaxTokensPerAccount bounds an account's device tokens. Past it a mint
// signs out the account's least recently used devices, so a loop of logins
// cannot grow the database without bound or slow every request the account
// makes, each of which reads all its tokens. A variable so a test can lower
// it.
var MaxTokensPerAccount = 200

// MaxLabelBytes bounds a device label; a longer one is cut at a character
// boundary.
const MaxLabelBytes = 128

// clampLabel cuts label to MaxLabelBytes without splitting a character.
func clampLabel(label string) string {
	if len(label) <= MaxLabelBytes {
		return label
	}
	cut := MaxLabelBytes
	for cut > 0 && !utf8.RuneStart(label[cut]) {
		cut--
	}
	return label[:cut]
}

// insertToken stores a new device token and answers the raw credential, the
// only moment it exists. The id is a global primary key, so it is wide enough
// that two mints cannot collide. keep names tokens the account's trim must
// not sign out (trimTokens).
func insertToken(tx *sql.Tx, name, label string, now time.Time, keep ...string) (string, error) {
	return insertTokenCreatedAt(tx, name, label, secs(now), keep...)
}

// insertTokenCreatedAt is insertToken recording createdAt verbatim.
func insertTokenCreatedAt(tx *sql.Tx, name, label string, createdAt time.Time, keep ...string) (string, error) {
	raw, id := "hd_u_"+randomHex(32), randomHex(8)
	if _, err := tx.Exec(`INSERT INTO tokens(id, username, sha256, label, created_at) VALUES(?, ?, ?, ?, ?)`,
		id, name, TokenHash(raw), clampLabel(label), toNS(createdAt)); err != nil {
		return "", err
	}
	return raw, trimTokens(tx, name, append(keep, id))
}

// trimTokens signs out the account's least recently used tokens past
// MaxTokensPerAccount, never one keep names.
func trimTokens(tx *sql.Tx, name string, keep []string) error {
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM tokens WHERE username = ?`, name).Scan(&n); err != nil {
		return err
	}
	if n <= MaxTokensPerAccount {
		return nil
	}
	rows, err := tx.Query(`SELECT id FROM tokens WHERE username = ? ORDER BY coalesce(last_used_at, created_at), id`, name)
	if err != nil {
		return err
	}
	ids, err := scanStrings(rows)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if n <= MaxTokensPerAccount {
			break
		}
		if slices.Contains(keep, id) {
			continue
		}
		if _, err := tx.Exec(`DELETE FROM tokens WHERE id = ?`, id); err != nil {
			return err
		}
		n--
	}
	return nil
}

func (db *DB) MintToken(name, label string) (raw string, err error) {
	return db.MintTokenCreatedAt(name, label, secs(time.Now()))
}

// MintTokenCreatedAt is MintToken for a token that continues a device's
// session, such as the replacement a password change hands the calling
// device: it records createdAt, the device's own sign-in time.
func (db *DB) MintTokenCreatedAt(name, label string, createdAt time.Time) (raw string, err error) {
	err = db.write(func(tx *sql.Tx) error {
		if _, err := scanUser(tx, name); err != nil {
			return err
		}
		raw, err = insertTokenCreatedAt(tx, name, label, createdAt)
		return err
	})
	return
}

// MintTokenIfPasswordIs mints a token only if the account's password hash
// still equals the one the caller authenticated against moments ago, and the
// second factor (if enrolled) accepts code. Login uses it so a password
// change between Authenticate and the mint cannot be raced.
func (db *DB) MintTokenIfPasswordIs(name, label, passwordHash, code string, now time.Time) (raw string, err error) {
	err = db.write(func(tx *sql.Tx) error {
		u, err := scanUser(tx, name)
		if err != nil {
			return err
		}
		if u.PasswordHash != passwordHash {
			return ErrBadCredentials
		}
		if err := db.checkSecondFactor(tx, &u, code, now); err != nil {
			return err
		}
		raw, err = insertToken(tx, name, label, now)
		return err
	})
	return
}

// UserByToken resolves a bearer token. The token's last-used stamp moves at
// most once an hour, so a busy client does not write on every request. The
// token row and the user are read together in one transaction. client is
// this request's X-HyperDrop-Client header, parsed; a non-empty value that
// differs from the row is written onto the token.
func (db *DB) UserByToken(raw string, client ClientInfo) (User, error) {
	h := TokenHash(raw)
	var u User
	var lastUsed sql.NullInt64
	var storedVersion string
	err := db.read(func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRow(`SELECT username, last_used_at, client_version FROM tokens WHERE sha256 = ?`, h).
			Scan(&name, &lastUsed, &storedVersion); err != nil {
			return err
		}
		var err error
		u, err = scanUser(tx, name)
		return err
	})
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrUserNotFound) {
		return User{}, ErrBadCredentials
	}
	if err != nil {
		return User{}, err
	}
	now := time.Now()
	if !u.Active(now) {
		return User{}, ErrInactive
	}
	stampUse := !lastUsed.Valid || now.Sub(fromNS(lastUsed.Int64)) > lastUsedGranularity
	newClient := !client.Empty() && client.Version != storedVersion
	stamp := toNS(secs(now))
	if stampUse || newClient {
		// Best-effort bookkeeping, both columns in one write transaction.
		_ = db.write(func(tx *sql.Tx) error {
			if stampUse {
				if _, err := tx.Exec(`UPDATE tokens SET last_used_at = ? WHERE sha256 = ?`, stamp, h); err != nil {
					return err
				}
			}
			if newClient {
				if _, err := tx.Exec(`UPDATE tokens SET client_version = ?, client_platform = ? WHERE sha256 = ?`,
					client.Version, client.Platform, h); err != nil {
					return err
				}
			}
			return nil
		})
	}
	for i := range u.Tokens {
		if u.Tokens[i].SHA256 != h {
			continue
		}
		if stampUse {
			u.Tokens[i].LastUsedAt = fromNS(stamp)
		}
		if newClient {
			u.Tokens[i].ClientVersion, u.Tokens[i].ClientPlatform = client.Version, client.Platform
		}
	}
	return u, nil
}

// ErrNoSuchToken is a revoke naming no token of the account.
var ErrNoSuchToken = &namedError{msg: "no such device token", is: ErrNotFound}

// RevokeToken deletes one of the account's tokens, answering ErrNoSuchToken
// when tokenID names none of them, another account's included.
func (db *DB) RevokeToken(name, tokenID string) error {
	return db.write(func(tx *sql.Tx) error {
		if _, err := scanUser(tx, name); err != nil {
			return err
		}
		res, err := tx.Exec(`DELETE FROM tokens WHERE username = ? AND id = ?`, name, tokenID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNoSuchToken
		}
		return nil
	})
}

// BcryptCost is the work factor of every password hash the server makes:
// account passwords here, share passwords in the api package. Tests lower
// it; nothing on a request path writes it.
var BcryptCost = bcrypt.DefaultCost
