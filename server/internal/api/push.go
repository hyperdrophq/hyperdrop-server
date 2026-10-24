package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"hyperdrop/core/pushseal"
	"hyperdrop/server/internal/metadb"
)

// DefaultPushRelay is the HyperDrop relay a server sends through unless
// HYPERDROP_PUSH_RELAY names another one (or is empty: push off).
const DefaultPushRelay = "https://api.gethyperdrop.com"

// ParsePushRelay checks the relay setting: an https origin (http only on a
// development server), answered without a trailing slash; "" is push off.
func ParsePushRelay(raw string, allowPrivate bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		strings.Trim(u.Path, "/") != "" || !(u.Scheme == "https" || (u.Scheme == "http" && allowPrivate)) {
		return "", errors.New("HYPERDROP_PUSH_RELAY must be an https origin such as " + DefaultPushRelay)
	}
	return u.Scheme + "://" + u.Host, nil
}

var (
	pushHandleShape = regexp.MustCompile(`^[0-9a-f]{32}$`)
	pushTagShape    = regexp.MustCompile(`^[A-Za-z0-9._-]{0,64}$`)
)

const maxPushMutes = 16

type pushRegistrationIn struct {
	Relay     string   `json:"relay"`
	Handle    string   `json:"handle"`
	PublicKey string   `json:"publicKey"`
	Tag       string   `json:"tag"`
	Muted     []string `json:"muted"`
}

// getPush answers the calling device's registration and the relay this
// server sends through ("" = push is off), which is where a phone registers.
// A registration made with another relay is never pushed to, so it reads as
// unregistered and the phone registers again. The handle is a capability and
// is never answered.
func (h *handler) getPush(w http.ResponseWriter, r *http.Request) {
	reg, ok, err := h.db.PushOf(metadb.TokenHash(bearerToken(r)))
	if err != nil {
		writeRefusal(w, err)
		return
	}
	if !ok || h.pushRelay == "" || reg.Relay != h.pushRelay {
		reg, ok = metadb.PushRegistration{}, false
	}
	muted := reg.Muted
	if muted == nil {
		muted = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"relay": h.pushRelay, "registered": ok, "tag": reg.Tag, "muted": muted})
}

// putPush attaches a push registration to the calling device's token row.
// The relay named in the body must be this server's own: the server only
// ever posts to the relay it was configured with, and compares the client's
// relay without dialling it.
func (h *handler) putPush(w http.ResponseWriter, r *http.Request) {
	var in pushRegistrationIn
	if !decodeJSONBody(w, r, 4096, &in) {
		return
	}
	if h.pushRelay == "" {
		writeErrorCode(w, http.StatusConflict, "push-off", "push is off on this server")
		return
	}
	if in.Relay != h.pushRelay {
		writeErrorCode(w, http.StatusConflict, "relay-mismatch",
			"this server sends notifications through "+h.pushRelay+"; register there")
		return
	}
	key, err := base64.StdEncoding.DecodeString(in.PublicKey)
	switch {
	case !pushHandleShape.MatchString(in.Handle):
		writeErrorCode(w, http.StatusBadRequest, "invalid", "handle: expected 32 lowercase hexadecimal characters")
		return
	case err != nil || pushseal.ParsePublicKey(key) != nil:
		writeErrorCode(w, http.StatusBadRequest, "invalid", "publicKey: expected a base64 X25519 public key")
		return
	case !pushTagShape.MatchString(in.Tag):
		writeErrorCode(w, http.StatusBadRequest, "invalid", "tag: up to 64 letters, digits, dots, underscores or hyphens")
		return
	case len(in.Muted) > maxPushMutes || slices.ContainsFunc(in.Muted, func(k string) bool { return !slices.Contains(metadb.PushKinds, k) }):
		writeErrorCode(w, http.StatusBadRequest, "invalid", "muted: up to 16 notification kinds")
		return
	}
	err = h.db.SetPush(metadb.TokenHash(bearerToken(r)), metadb.PushRegistration{
		Relay: in.Relay, Handle: in.Handle, PublicKey: key, Tag: in.Tag, Muted: in.Muted})
	switch {
	case errors.Is(err, metadb.ErrBadPush):
		// Every other part of ErrBadPush is refused above; a muted kind is
		// what metadb checks again.
		writeErrorCode(w, http.StatusBadRequest, "invalid", "muted: up to 16 notification kinds")
		return
	case err != nil:
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"registered": true})
}

// deletePush removes the calling device's registration.
func (h *handler) deletePush(w http.ResponseWriter, r *http.Request) {
	if err := h.db.ClearPush(metadb.TokenHash(bearerToken(r))); err != nil {
		writeRefusal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// putActivity records whether a computer's owner is at it. The server
// leaves announcing to a computer of the account that saw its owner within
// desktopIdleLimit; anything else clears the mark.
func (h *handler) putActivity(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OnConsole   bool `json:"onConsole"`
		IdleSeconds int  `json:"idleSeconds"`
	}
	if !decodeJSONBody(w, r, 1024, &in) {
		return
	}
	// Bounded before it is multiplied: a huge idleSeconds would overflow the
	// Duration and stamp the activity in the future.
	var at *time.Time
	if in.OnConsole && in.IdleSeconds >= 0 && in.IdleSeconds < int(desktopIdleLimit/time.Second) {
		t := time.Now().Add(-time.Duration(in.IdleSeconds) * time.Second)
		at = &t
	}
	if err := h.db.SetConsoleActivity(metadb.TokenHash(bearerToken(r)), at); err != nil {
		writeRefusal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
