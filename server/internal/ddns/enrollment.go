package ddns

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Enrollment is short-lived account approval state, stored beside the private
// machine credential so both survive a restart. Challenge is public reachability
// proof, but only ApprovalURL and ExpiresAt belong in client-facing status.
type Enrollment struct {
	ApprovalURL string `json:"approvalURL"`
	Challenge   string `json:"challenge"`
	ExpiresAt   int64  `json:"expiresAt"`
}

func (u *Updater) rememberEnrollment(e *ServiceError) error {
	approval, err := url.Parse(e.ApprovalURL)
	if err != nil || approval.Scheme != "https" || approval.Host != "gethyperdrop.com" || approval.User != nil || approval.Path != "/account/" {
		return errors.New("names service returned an invalid account approval address")
	}
	if e.Challenge == "" || len(e.Challenge) > 256 || strings.IndexFunc(e.Challenge, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_')
	}) >= 0 || e.ExpiresAt <= u.Now().Unix() {
		return errors.New("names service returned an invalid account approval challenge")
	}
	return u.store.change(func(s *State) {
		s.Enrollment = &Enrollment{ApprovalURL: e.ApprovalURL, Challenge: e.Challenge, ExpiresAt: e.ExpiresAt}
	})
}

// ServeEnrollmentChallenge must not acquire tickMu: the registry calls this
// while Choose holds that lock and waits for its claim response.
func (u *Updater) ServeEnrollmentChallenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	s := u.store.Snapshot()
	if !s.Pending || s.Enrollment == nil || s.Enrollment.ExpiresAt <= u.Now().Unix() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"challenge": s.Enrollment.Challenge})
}
