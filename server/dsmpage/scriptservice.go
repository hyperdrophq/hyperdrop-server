package dsmpage

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"time"
)

// The Service over the package's start-stop-status script.

// scriptPATH is the PATH the worker and the start script run with.
const scriptPATH = "/usr/syno/sbin:/usr/syno/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// scriptService runs the package's start-stop-status as DSM does, with the
// facts its scripts read from DSM's environment.
type scriptService struct {
	p      *page
	script string
	client *http.Client
}

func newScriptService(p *page) *scriptService {
	return &scriptService{
		p:      p,
		script: p.deps.Script,
		client: &http.Client{
			Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Stop waits up to the script's own 30 seconds and its kill, Start for the
// script alone, which watches the server it starts for its first seconds
// and fails when it exits; the server runs on in the background.
func (s *scriptService) Stop() error  { return s.run("stop", 90*time.Second) }
func (s *scriptService) Start() error { return s.run("start", 60*time.Second) }

func (s *scriptService) run(arg string, limit time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.script, arg)
	cmd.Dir = "/"
	cmd.Env = []string{
		"PATH=" + scriptPATH,
		"SYNOPKG_PKGNAME=hyperdrop",
		"SYNOPKG_PKGDEST=" + packageTarget,
		"SYNOPKG_PKGVAR=" + s.p.deps.VarDir,
	}
	cmd.WaitDelay = time.Second
	return cmd.Run()
}

func (s *scriptService) Running() bool { return s.p.running() }

// Healthy is true when the server's plain-HTTP health route on loopback,
// on the port the conf names now, answers 200 with HyperDrop's own health
// document, which carries its serverID: another program answering on the
// port is not HyperDrop.
func (s *scriptService) Healthy(ctx context.Context) bool {
	port := portOf(readConf(s.p.deps.ConfPath)["HTTP_ADDR"])
	if port == 0 {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/api/health", nil)
	if err != nil {
		return false
	}
	res, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	var health struct {
		ServerID string `json:"serverID"`
	}
	if res.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&health) != nil {
		return false
	}
	return health.ServerID != ""
}
