package dsmpage

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// On DSM 6 the page asks DSM who is signed in through DSM's own web API,
// as the package user, with the request's own session cookie: one GET to
// SYNO.Core.NormalUser get on 127.0.0.1, at the scheme and port DSM's web
// server received the request on (its CGI environment names them), which
// answers the session's user name for every class of user and a refusal
// (error 119) for a cookie DSM does not know, whether forged, logged out
// or expired. A session DSM's login page made is bound to the browser's
// address and requires the session's token on the web API: DSM answers
// error 150 and ends the session when a call comes from another address,
// and error 105 for a wrong or missing token. So the call carries the
// request's own client address in X-Forwarded-For, which DSM's web server
// trusts from loopback alone and reads as the client, and the request's
// token header. A session the API made is bound to neither; both kinds
// answer the same way to this call.

// webAPIPath is the query that names the session's user.
const webAPIPath = "/webapi/entry.cgi?api=SYNO.Core.NormalUser&version=1&method=get"

// webAPIBodyLimit is the most of DSM's answer the check reads; the real
// answer is a few hundred bytes.
const webAPIBodyLimit = 64 << 10

var errNotForwardable = errors.New("dsmpage: the request carries no DSM session to check")

// webAPIAuthenticate answers the DSM user signed in to the request whose
// CGI environment env is, or an error for a request DSM does not know. A
// request without a cookie, a client address, a scheme or a port is
// refused without dialling.
func webAPIAuthenticate(ctx context.Context, env []string) (string, error) {
	scheme, port, ok := sessionTargetIn(env)
	cookie := envValue(env, "HTTP_COOKIE")
	client := envValue(env, "REMOTE_ADDR")
	host := envValue(env, "HTTP_HOST")
	if !ok || cookie == "" || net.ParseIP(client) == nil || !headerValueOK(cookie) || !hostOK(host) {
		return "", errNotForwardable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://127.0.0.1:"+port+webAPIPath, nil)
	if err != nil {
		return "", err
	}
	if host != "" {
		// The browser's Host header picks the server block DSM's web
		// server answered the request from (DSM reached through a
		// customised domain has one of its own); the dial stays loopback.
		req.Host = host
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("X-Forwarded-For", client)
	if tok := envValue(env, "HTTP_X_SYNO_TOKEN"); tok != "" {
		if !headerValueOK(tok) {
			return "", errNotForwardable
		}
		req.Header.Set("X-SYNO-TOKEN", tok)
	}
	res, err := loopbackClient(port).Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("dsmpage: DSM answered %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, webAPIBodyLimit+1))
	if err != nil {
		return "", err
	}
	if len(body) > webAPIBodyLimit {
		return "", errors.New("dsmpage: DSM's answer is too long")
	}
	var answer struct {
		Success bool `json:"success"`
		Data    struct {
			Username string `json:"username"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return "", err
	}
	if !answer.Success || answer.Data.Username == "" {
		return "", errors.New("dsmpage: DSM names no user for the session")
	}
	return answer.Data.Username, nil
}

// sessionTargetIn reads the scheme and port DSM's web server received the
// request on: REQUEST_SCHEME (http or https), with HTTPS=on also meaning
// https, and SERVER_PORT, a plain port number. Anything else is no target.
func sessionTargetIn(env []string) (scheme, port string, ok bool) {
	scheme = envValue(env, "REQUEST_SCHEME")
	if envValue(env, "HTTPS") == "on" {
		scheme = "https"
	}
	if scheme != "http" && scheme != "https" {
		return "", "", false
	}
	port = envValue(env, "SERVER_PORT")
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return "", "", false
	}
	return scheme, port, true
}

// headerValueOK answers whether v can travel as one header value: no
// control character, so nothing in it can end the header or start another.
func headerValueOK(v string) bool {
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// hostOK answers whether h can travel as a Host header: one token, no
// control character and no space.
func hostOK(h string) bool {
	return headerValueOK(h) && !strings.ContainsAny(h, " /\\?#@")
}

// envValue answers the value of name in a CGI environment, "" when unset.
func envValue(env []string, name string) string {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, name+"="); ok {
			return v
		}
	}
	return ""
}

// loopbackClient makes the one call to DSM on 127.0.0.1:port: it dials
// nothing else whatever the URL names, consults no proxy, keeps no
// connection, follows no redirect and, over https, accepts DSM's own
// certificate (the trust is the loopback port, which DSM's web server
// holds).
func loopbackClient(port string) *http.Client {
	tr := &http.Transport{
		Proxy:             nil,
		DialContext:       loopbackDial(port),
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("dsmpage: DSM redirected the session check")
		},
	}
}

// loopbackDial dials 127.0.0.1:port whatever address it is handed.
func loopbackDial(port string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp4", "127.0.0.1:"+port)
	}
}
