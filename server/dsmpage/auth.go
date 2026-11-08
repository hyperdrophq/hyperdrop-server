package dsmpage

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"
)

// authenticateCGI prints the DSM user signed in to the request whose CGI
// environment it runs with. On DSM 7 it prints nothing unless that request
// carries DSM's X-SYNO-TOKEN header; on DSM 6 the session cookie alone is
// enough, and only root may run it (root.go runs it before the CGI becomes
// the package user).
const authenticateCGI = "/usr/syno/synoman/webman/modules/authenticate.cgi"

// commandTimeout bounds each DSM program the check runs.
const commandTimeout = 5 * time.Second

// dsmUser is the shape of a DSM user name the check accepts: local, LDAP
// (user@domain) and nothing that could read as a second word or an option
// to id beyond the "--" that precedes it.
var dsmUser = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

// pageError is a refusal whose text is the sentence the page shows as it is.
type pageError string

func (e pageError) Error() string { return string(e) }

var (
	errSignIn   error = pageError("Sign in to DSM again.")
	errNotAdmin error = pageError("Only DSM administrators can use this page.")
	errGroups   error = pageError("Could not read your DSM groups. Try again.")
)

// requireDSMAdmin answers the DSM user behind the request when that user is
// in DSM's administrators group, and otherwise the status code and error to
// answer. A request without the token header is refused before anything
// runs, on both DSM generations. The header means two things: on DSM 7 DSM
// verifies it (authenticate.cgi names nobody without a valid one); on DSM 6
// nothing verifies it, and it is the cross-site guard alone, because a page
// on another origin cannot put a custom header on a request without a CORS
// preflight DSM never answers, and nothing on another origin can read the
// token from DSM.
func (p *page) requireDSMAdmin(r *http.Request) (string, int, error) {
	if r.Header.Get("X-SYNO-TOKEN") == "" {
		return "", http.StatusUnauthorized, errSignIn
	}
	ctx, cancel := context.WithTimeout(r.Context(), commandTimeout)
	user, err := p.deps.Authenticate(ctx, p.deps.Environ())
	cancel()
	user = strings.TrimSpace(user)
	if err != nil || !dsmUser.MatchString(user) {
		return "", http.StatusUnauthorized, errSignIn
	}
	ctx, cancel = context.WithTimeout(r.Context(), commandTimeout)
	groups, err := p.deps.Groups(ctx, user)
	cancel()
	if err != nil {
		return "", http.StatusInternalServerError, errGroups
	}
	if !slices.Contains(groups, "administrators") {
		return "", http.StatusForbidden, errNotAdmin
	}
	return user, 0, nil
}

// runAuthenticate runs DSM's authenticate.cgi with the CGI request's
// environment and answers what it prints, trimmed. Its stdin is empty, so
// it never reads the request body.
func runAuthenticate(ctx context.Context, program string, env []string) (string, error) {
	cmd := exec.CommandContext(ctx, program)
	cmd.Env = env
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// runGroups answers the words of `id -Gn -- user`.
func runGroups(ctx context.Context, program, user string) ([]string, error) {
	cmd := exec.CommandContext(ctx, program, "-Gn", "--", user)
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(bytes.TrimSpace(out))), nil
}

// idProgram is id's path on DSM, where a CGI's PATH may be minimal.
func idProgram() string {
	for _, p := range []string{"/usr/bin/id", "/bin/id"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "id"
}
