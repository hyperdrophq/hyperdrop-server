package scenario

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	"hyperdrop/server/internal/loadrig/report"
	"hyperdrop/server/internal/loadrig/target"
	"hyperdrop/server/internal/loadrig/volume"
)

const (
	opSignIn       = "sign in"
	opSignOut      = "sign out"
	opAccountList  = "list page x64 (every account)"
	opAccountUsage = "usage (/api/me) x64 (every account)"

	valSignInSample  = "sign-in sample"
	valSignedIn      = "signed in"
	valSignInRefused = "sign-in refusals (429 or 503 busy)"
	valSignInLimit   = "sign-in limit that refused"
	valAccounts      = "accounts listed"

	// signInSample is how many accounts sign in, scaled, and never fewer
	// than signInLeast: each sign-in is a bcrypt compare the server keeps
	// deliberately slow, so every account of a large volume would take hours.
	signInSample = 200
	signInLeast  = 5
	// accountWorkers is how many accounts read at once in the listing part.
	accountWorkers = 64
	// signInLabel names the device each sign-in mints.
	signInLabel = "loadrig sign-in"
)

var accountsScenario = Scenario{
	Name: "accounts",
	About: "Many accounts: a sample of 200 accounts (at least 5) signs in one after another from one address with " +
		"the volume's password, each signing its new device out again, the sign-in limits' refusals counted as " +
		"answers; then every account of the volume, 64 at once, asks for its listing page and its usage with its " +
		"own token.",
	Run: accounts,
}

func accounts(ctx context.Context, e Env, rec *report.Recorder) error {
	if len(e.Volume.Accounts) == 0 {
		return Skip("the volume's manifest carries no accounts")
	}
	if err := signIns(ctx, e, rec); err != nil {
		return err
	}

	var listed []volume.Account
	for _, a := range e.Volume.Accounts {
		if a.Token != "" {
			listed = append(listed, a)
		}
	}
	rec.Value(valAccounts, float64(len(listed)), "accounts")
	var next atomic.Int64
	more := func(int) bool { return next.Load() < int64(len(listed)) }
	return parallel(ctx, e, rec, min(accountWorkers, len(listed)), more, func(_ int, c *target.Client) error {
		k := next.Add(1) - 1
		if k >= int64(len(listed)) {
			return nil
		}
		a := listed[k]
		errList := firstPage(ctx, c, opAccountList, a.Token)
		if err := me(ctx, c, opAccountUsage, a.Token, a.Name); err != nil {
			return err
		}
		return errList
	})
}

// signIns signs the sample's accounts in one after another through the
// login route, and each one's new device out again: the server keeps a
// bounded number of devices per account and signs the least recently used
// out past it. A refusal by the server's sign-in limits is an answer; the
// first one's reason is reported.
func signIns(ctx context.Context, e Env, rec *report.Recorder) error {
	n := min(e.Plan.Accounts, max(signInLeast, e.times(signInSample)))
	rec.Value(valSignInSample, float64(n), "accounts")
	rec.Value(valSources, 1, "addresses")
	c := e.client(rec, 0)
	defer c.Close()
	signedIn, refused := 0, 0
	limit := ""
	for i := range n {
		name := e.Plan.Account(i)
		body, err := json.Marshal(map[string]string{"username": name, "password": volume.Password, "label": signInLabel})
		if err != nil {
			return err
		}
		var token string
		err = c.Do(ctx, opSignIn, http.MethodPost, "/api/auth/login", "", bytes.NewReader(body), func(r *http.Response) error {
			if refusedByLimit(r) {
				refused++
				if limit == "" {
					limit = refusalReason(r)
				}
				return nil
			}
			var out struct {
				Token string `json:"token"`
				User  struct {
					Username string `json:"username"`
				} `json:"user"`
			}
			if err := decodeOK(r, &out); err != nil {
				return err
			}
			if out.Token == "" || out.User.Username != name {
				return fmt.Errorf("signed in as %s, answered a token for %q", name, out.User.Username)
			}
			token = out.Token
			return nil
		})
		if err != nil && !answering(e.Target) {
			return errStopped
		}
		if token == "" {
			continue
		}
		signedIn++
		if err := c.Do(ctx, opSignOut, http.MethodDelete, "/api/auth/token", token, nil, wantStatus(http.StatusNoContent)); err != nil && !answering(e.Target) {
			return errStopped
		}
	}
	rec.Value(valSignedIn, float64(signedIn), "accounts")
	rec.Value(valSignInRefused, float64(refused), "answers")
	if refused > 0 {
		rec.NotAvailable(valSignInLimit, fmt.Sprintf("%d of %d sign-ins from one address were refused, the first with %s", refused, n, limit))
	}
	return nil
}

// refusalReason is a refusal's status, code and sentence, as the server
// worded it.
func refusalReason(r *http.Response) string {
	var body struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	return strings.TrimSpace(fmt.Sprintf("%d %s %q", r.StatusCode, body.Code, body.Error))
}
