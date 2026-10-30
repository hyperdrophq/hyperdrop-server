package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"hyperdrop/server/internal/metadb"
)

// The known-browser cookie marks a browser where an account signed in with
// "This is my computer". It grants nothing but a lane: the web sign-in of
// that account from that browser counts on the cookie's own lane
// (knownLaneKey) in place of the account name's stranger lane, so strangers
// guessing at the account do not slow its owner's own browser. Only a
// successful kept web sign-in sets it, only the web sign-in reads it, and
// the server never clears it: the browser holds one at a time, each kept
// sign-in replacing it. A sign-out and the web switch leave it holding; a
// password change or an administrator's reset of the password makes every
// cookie of the account stop holding, and the next kept sign-in mints one
// that holds.
//
// Its value is k1.<id>.<issued>.<mac>: id is 16 random bytes and mac an
// HMAC-SHA256 under h.knownKey, both base64url without padding, and issued
// the decimal Unix seconds of the sign-in. The MAC covers
// "k1|<username>|<the account's CreatedAt, Unix seconds>|<the stored
// password hash>|<id>|<issued>" (a bcrypt hash holds no "|", so the fields
// stay apart), so a cookie holds only for the account it was minted for, as
// that account exists now and while it keeps that password: an account deleted
// and created again under the same name in a later second holds none of the
// old one's cookies, and each password set (a change, a reset) writes a new
// hash, which voids the cookies minted under the one before. Whoever once
// knew a password therefore gains no lane under the next one.

// knownCookie names the known-browser cookie. The __Host- prefix makes the
// browser refuse it unless it is Secure, Path=/ and carries no Domain, so it
// never reaches files.<domain>.
const knownCookie = "__Host-hd_known"

// knownFor is how long a known-browser cookie holds after it is issued, and
// its Max-Age.
const knownFor = 180 * 24 * time.Hour

// knownKeyInfo names the known-browser MAC key among the volume secret's
// subkeys.
const knownKeyInfo = "known-browser"

const (
	knownVersion = "k1"
	knownIDLen   = 22
	knownMACLen  = 43
	// knownIssuedMax bounds the issued field's characters: an int64 has 19
	// decimal digits.
	knownIssuedMax = 19
	// knownValueMax bounds a value worth parsing; a longer one is refused
	// before it is split or decoded.
	knownValueMax = len(knownVersion) + 1 + knownIDLen + 1 + knownIssuedMax + 1 + knownMACLen
)

// knownMAC is the MAC of a known-browser cookie of account u, under its
// stored password hash, carrying id and issued, under key.
func knownMAC(key []byte, u metadb.User, id, issued string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(knownVersion + "|" + u.Username + "|" + strconv.FormatInt(u.CreatedAt.Unix(), 10) + "|" + u.PasswordHash + "|" + id + "|" + issued))
	return m.Sum(nil)
}

// mintKnownCookie sets a fresh known-browser cookie for account u, issued at
// now. It sets nothing when the server has no known-browser key.
func (h *handler) mintKnownCookie(w http.ResponseWriter, u metadb.User, now time.Time) {
	if len(h.knownKey) == 0 {
		return
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return
	}
	id := base64.RawURLEncoding.EncodeToString(raw)
	issued := strconv.FormatInt(now.Unix(), 10)
	mac := base64.RawURLEncoding.EncodeToString(knownMAC(h.knownKey, u, id, issued))
	http.SetCookie(w, &http.Cookie{
		Name: knownCookie, Value: knownVersion + "." + id + "." + issued + "." + mac,
		Path: "/", MaxAge: int(knownFor / time.Second), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

// knownBrowser answers the id of the known-browser cookie r carries when it
// holds for the account username at now: well formed, issued no later than
// now and less than knownFor before it, and its MAC that of the account as
// it exists now, its stored password hash included. Any other cookie, or none, answers ("", false), and the
// sign-in counts as a stranger's. The value is parsed in full before the
// account is read, and a value longer than knownValueMax is never split or
// decoded. The caller has already checked the request with
// webCookieAccepted.
func (h *handler) knownBrowser(r *http.Request, username string, now time.Time) (id string, ok bool) {
	if len(h.knownKey) == 0 {
		return "", false
	}
	c, err := r.Cookie(knownCookie)
	if err != nil || len(c.Value) > knownValueMax {
		return "", false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 4 || parts[0] != knownVersion {
		return "", false
	}
	id, issuedText, macText := parts[1], parts[2], parts[3]
	if len(id) != knownIDLen || len(macText) != knownMACLen || issuedText == "" || len(issuedText) > knownIssuedMax {
		return "", false
	}
	// Strict decoding refuses a non-canonical encoding, so one id has one
	// spelling and one lane.
	strict := base64.RawURLEncoding.Strict()
	if raw, err := strict.DecodeString(id); err != nil || len(raw) != 16 {
		return "", false
	}
	mac, err := strict.DecodeString(macText)
	if err != nil || len(mac) != sha256.Size {
		return "", false
	}
	issuedSecs, err := strconv.ParseInt(issuedText, 10, 64)
	if err != nil || strconv.FormatInt(issuedSecs, 10) != issuedText {
		return "", false
	}
	issued := time.Unix(issuedSecs, 0)
	if now.Before(issued) || !now.Before(issued.Add(knownFor)) {
		return "", false
	}
	u, err := h.db.User(username)
	if err != nil {
		return "", false
	}
	if !hmac.Equal(mac, knownMAC(h.knownKey, u, id, issuedText)) {
		return "", false
	}
	return id, true
}
