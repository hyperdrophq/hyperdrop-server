package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"hyperdrop/server/internal/loadrig/target"
	"hyperdrop/server/internal/totp"
)

// TestBootServesAndDrains builds the server binary and runs it the way an
// operator does, on the plain-HTTP development path against an empty data
// directory, to pin main()'s wiring end to end: the health route answers,
// the administrator is seeded from the environment, a share is created,
// uploaded to and downloaded byte for byte, housekeeping runs its first
// pass, and SIGTERM drains a parked watch and ends the process with exit 0
// inside the shutdown grace (shutdownGrace). A drained server exits well
// inside it: Drain answers every parked long-poll at once, so Shutdown has
// no request left to wait for.
func TestBootServesAndDrains(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the server")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	bin, err := target.BuildServer(ctx, ".", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// StartLocal returns once /api/health answers status "ok".
	tg, err := target.StartLocal(ctx, bin, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tg.Close() })
	c := bootClient{t: t, base: tg.BaseURL()}

	var health struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	c.json("GET", "/api/health", "", nil, http.StatusOK, &health)
	if health.Status != "ok" || health.Version != version {
		t.Fatalf("health = %+v, want ok at %s", health, version)
	}

	var login struct {
		Token string `json:"token"`
		User  struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		} `json:"user"`
	}
	c.json("POST", "/api/auth/login", "", map[string]any{
		"username": target.AdminUser, "password": target.AdminPassword, "label": "boot test",
	}, http.StatusOK, &login)
	if login.Token == "" || login.User.Username != target.AdminUser || login.User.Role != "admin" {
		t.Fatalf("sign-in = %+v, want the seeded administrator", login)
	}
	token := login.Token

	// An administrator owes a second factor before it may create a share.
	var start struct {
		Secret string `json:"secret"`
	}
	c.json("POST", "/api/me/totp", token, map[string]any{"currentPassword": target.AdminPassword}, http.StatusOK, &start)
	code, err := totp.Code(start.Secret, totp.StepAt(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	c.json("POST", "/api/me/totp/confirm", token, map[string]any{"code": code}, http.StatusOK, nil)

	content := []byte("hyperdrop boot test\n" + strings.Repeat("0123456789", 1000))
	var share struct {
		ID string `json:"id"`
	}
	c.json("POST", "/api/shares", token, map[string]any{"name": "boot test", "reserveBytes": len(content)}, http.StatusCreated, &share)
	if share.ID == "" {
		t.Fatal("a created share without an id")
	}
	put := c.request("PUT", "/api/shares/"+share.ID+"/files/boot.txt", token, bytes.NewReader(content))
	put.Header.Set("Upload-Session", "boot-test")
	put.Header.Set("Upload-Total", strconv.Itoa(len(content)))
	put.Header.Set("Upload-Range", "0-"+strconv.Itoa(len(content)))
	var file struct {
		Path string `json:"path"`
		Size int    `json:"size"`
		Slug string `json:"slug"`
	}
	c.do(put, http.StatusCreated, &file)
	if file.Path != "boot.txt" || file.Size != len(content) || file.Slug == "" {
		t.Fatalf("upload = %+v, want boot.txt of %d bytes with a slug", file, len(content))
	}
	// The owner's bearer fetch: an anonymous download counts a visit, whose
	// flush writes a journal row that would wake the watch parked below.
	got := c.body(c.request("GET", "/download/"+share.ID+"/"+file.Slug, token, nil), http.StatusOK)
	if !bytes.Equal(got, content) {
		t.Fatalf("downloaded %d bytes that differ from the %d uploaded", len(got), len(content))
	}

	lctx, lcancel := context.WithTimeout(ctx, 2*time.Minute)
	defer lcancel()
	if _, err := tg.WaitLog(lctx, "housekeeping first pass: "); err != nil {
		t.Fatal(err)
	}

	// A watch parked on the current cursor holds a request open, which only
	// Drain answers before the grace runs out. It must answer after SIGTERM
	// and with no change, or something other than Drain released it.
	type watchAnswer struct {
		Cursor  string `json:"cursor"`
		Changed bool   `json:"changed"`
	}
	var cursor watchAnswer
	c.json("GET", "/api/shares/watch", token, nil, http.StatusOK, &cursor)
	type watchResult struct {
		answer watchAnswer
		at     time.Time
		err    error
	}
	watched := make(chan watchResult, 1)
	sent := make(chan struct{})
	var sentOnce sync.Once
	go func() {
		var res watchResult
		req := c.request("GET", "/api/shares/watch?since="+cursor.Cursor, token, nil)
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			WroteRequest: func(httptrace.WroteRequestInfo) { sentOnce.Do(func() { close(sent) }) },
		}))
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			switch {
			case resp.StatusCode != http.StatusOK:
				err = fmt.Errorf("answered %d %s", resp.StatusCode, b)
			default:
				err = json.Unmarshal(b, &res.answer)
			}
		}
		res.at, res.err = time.Now(), err
		watched <- res
	}()
	select {
	case <-sent:
	case <-time.After(30 * time.Second):
		t.Fatal("the watch request was never sent")
	}
	// Only the server's side of the hand-off is left to wait for.
	time.Sleep(500 * time.Millisecond)

	began := time.Now()
	err = tg.Close()
	took := time.Since(began)
	if err != nil {
		t.Fatalf("after SIGTERM the server exited with %v, want exit 0", err)
	}
	t.Logf("exit 0, %v after SIGTERM", took.Round(time.Millisecond))
	if took >= shutdownGrace {
		t.Fatalf("the server took %v to stop after SIGTERM, want under %v", took, shutdownGrace)
	}
	res := <-watched
	if res.err != nil {
		t.Fatalf("the parked watch: %v, want Drain's answer", res.err)
	}
	if res.at.Before(began) || res.answer.Changed || res.answer.Cursor != cursor.Cursor {
		t.Fatalf("the parked watch answered %+v %v after SIGTERM, want Drain's unchanged answer after it",
			res.answer, res.at.Sub(began))
	}
	lines, _ := tg.Log()
	if !slices.ContainsFunc(lines, func(l string) bool { return strings.HasSuffix(l, "shutting down") }) {
		t.Fatal(`the server did not log "shutting down"`)
	}
	// The boot phases are timed: each line appears once, in the order the
	// phases run, before the listener starts.
	serving := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, "serving HTTP") })
	if serving < 0 {
		t.Fatal(`the server did not log "serving HTTP"`)
	}
	at := -1
	for _, prefix := range []string{"boot: database check: ", "boot: schema: ", "boot: store: ", "boot: share ids: ",
		"boot pass: ", "boot: publishes: ", "boot: volume ready: "} {
		var found []int
		for i, l := range lines {
			if strings.HasPrefix(l[min(len(l), len("2006/01/02 15:04:05 ")):], prefix) {
				found = append(found, i)
			}
		}
		if len(found) != 1 || found[0] <= at || found[0] >= serving {
			t.Fatalf("%q is at lines %v, want once after line %d and before serving at %d\n%s",
				prefix, found, at, serving, strings.Join(lines, "\n"))
		}
		at = found[0]
	}
	// The boot pass's sweep runs once the API phase starts, after the volume
	// is ready, and logs one line.
	var swept []int
	for i, l := range lines {
		if strings.HasPrefix(l[min(len(l), len("2006/01/02 15:04:05 ")):], "boot sweep: ") {
			swept = append(swept, i)
		}
	}
	if len(swept) != 1 || swept[0] <= at {
		t.Fatalf("\"boot sweep: \" is at lines %v, want once after line %d\n%s", swept, at, strings.Join(lines, "\n"))
	}
}

// A SIGTERM closes the database cleanly and records it, so the next start
// skips the check; a SIGKILL leaves no record, so the start after it checks.
// Each start answers healthy.
func TestACleanRestartSkipsTheCheckAndAKilledOneDoesNot(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the server")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	bin, err := target.BuildServer(ctx, ".", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tg, err := target.StartLocal(ctx, bin, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tg.Close() })
	c := bootClient{t: t, base: tg.BaseURL()}
	checkLine := func(want string) {
		t.Helper()
		lctx, lcancel := context.WithTimeout(ctx, time.Minute)
		defer lcancel()
		line, err := tg.WaitLog(lctx, "boot: database check: ")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(line, want) {
			t.Fatalf("%q, want it to say %q", line, want)
		}
		c.json("GET", "/api/health", "", nil, http.StatusOK, nil)
	}
	checkLine("checked: no record")

	if _, err := tg.Restart(ctx); err != nil {
		t.Fatal(err)
	}
	lines, _ := tg.Log()
	if !slices.ContainsFunc(lines, func(l string) bool {
		return strings.HasSuffix(l, "database: closed cleanly; the next start skips its check")
	}) {
		t.Fatalf("the stopped server did not record its clean close:\n%s", strings.Join(lines, "\n"))
	}
	checkLine("skipped: closed cleanly")

	if _, err := tg.RestartKilled(ctx); err != nil {
		t.Fatal(err)
	}
	checkLine("checked: no record")
}

// bootClient is the plain HTTP client TestBootServesAndDrains signs in and
// shares through.
type bootClient struct {
	t    *testing.T
	base string
}

func (c bootClient) request(method, path, token string, body io.Reader) *http.Request {
	c.t.Helper()
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		c.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// body sends req and answers its body, failing unless it answers want.
func (c bootClient) body(req *http.Request, want int) []byte {
	c.t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	if resp.StatusCode != want {
		c.t.Fatalf("%s %s = %d %s, want %d", req.Method, req.URL.Path, resp.StatusCode, b, want)
	}
	return b
}

// do sends req and decodes its JSON answer into out (nil reads nothing).
func (c bootClient) do(req *http.Request, want int, out any) {
	c.t.Helper()
	b := c.body(req, want)
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			c.t.Fatalf("%s %s: %v in %s", req.Method, req.URL.Path, err, b)
		}
	}
}

// json sends in as a JSON body (nil sends none) and decodes the answer.
func (c bootClient) json(method, path, token string, in any, want int, out any) {
	c.t.Helper()
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			c.t.Fatal(err)
		}
		body = bytes.NewReader(b)
	}
	req := c.request(method, path, token, body)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.do(req, want, out)
}
