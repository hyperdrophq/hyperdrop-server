package scenario

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"hyperdrop/server/internal/loadrig/report"
	"hyperdrop/server/internal/loadrig/target"
	"hyperdrop/server/internal/loadrig/volume"
)

const (
	opCreateShare        = "create share"
	opPastCap            = "upload file past cap"
	opCreateWithManifest = "create with manifest"
	opCreateBatchShare   = "create share (batches)"
	opCreateOne          = "create one-file share"
	opUploadOne          = "upload one file"

	valUploadAccount       = "upload account index"
	valFilesUploaded       = "files uploaded one at a time"
	valFillTook            = "upload fill took"
	valShareFiles          = "upload share file count"
	valPastCap             = "file past the file cap"
	valGrowth              = "upload median, last window over first"
	valManifestFiles       = "manifest files"
	valPendingUploaded     = "pending files uploaded"
	valManifestShareFiles  = "manifest share file count"
	valBatchFilesUploaded  = "files uploaded in batches"
	valBatchTook           = "batch fill took"
	valBatchShareFiles     = "batch share file count"
	valSharesCreated       = "shares created"
	valCreateRate          = "one-file shares per second"
	valCreateRefusals      = "create refusals (429 or 503 busy)"
	valCreateAccounts      = "accounts creating"
	valCreateBurst         = "create limit per account (burst)"
	valCreatePerHour       = "create limit per account per hour"
	valClientManifestFiles = "client manifest bound"
	valClientBatchFiles    = "client batch size"

	// uploadAccount is the plan's account the fills upload as, when it has
	// no quota.
	uploadAccount = 2
	// uploadLeast is the fewest files a fill below scale 1 uploads.
	uploadLeast = 300
	// uploadWindow is how many files one row of the per-file cost covers.
	uploadWindow = 1000
	// uploadFileSize is each uploaded file's size.
	uploadFileSize = 1 << 10
	// createHold is how long the share creation runs, scaled.
	createHold = 20 * time.Second
	// createWorkers is how many clients create shares at once.
	createWorkers = 16
	// oneFileName is the file of every one-file share.
	oneFileName = "note.txt"

	// clientManifestFiles is core/api's manifestMaxFiles: the most files the
	// desktop client lists in a create's manifest. A larger selection is
	// created with no manifest and its files join the share as they commit.
	clientManifestFiles = 2000
	// clientBatchFiles is core/api's batchMaxFiles: how many small files the
	// desktop client sends in one tar request to the batch route.
	clientBatchFiles = 500
)

// The ops each window of files is recorded under, the window holding file f,
// counting from 1.
func uploadWindowOp(f int) string  { return windowOp("upload file", f) }
func pendingWindowOp(f int) string { return windowOp("upload pending file", f) }
func batchWindowOp(f int) string   { return windowOp("upload batch, files", f) }

func windowOp(prefix string, f int) string {
	lo := (f-1)/uploadWindow*uploadWindow + 1
	return fmt.Sprintf("%s %d-%d", prefix, lo, lo+uploadWindow-1)
}

var uploadScenario = Scenario{
	Name: "upload",
	About: "Uploading into a big share, as one account without a quota, with 1 KiB files. The desktop client " +
		"creates a share for a folder of more than 2,000 files with the upload size reserved and no manifest " +
		"(core/api/shares.go), so its files join the share as they commit; it is filled through the per-file " +
		"upload route, one file after another, to the file cap (below scale 1, to the cap times the scale and " +
		"at least 300), the cost reported per 1,000 files so its growth with the share's size is one table; at " +
		"the cap, one file more. The client itself sends files under 8 MiB in tar batches of 500, so a second " +
		"share is filled to the same size through the batch route. A third share is created with a manifest of " +
		"2,000 files (the most the client lists, scaled like the fill) and its pending files completed one PUT " +
		"each. Then 16 clients create one-file shares for 20 s, each moving to the next account every round: on a " +
		"volume of few accounts the create limit (100 at once, 600 an hour per account) refuses some, on one of " +
		"thousands no account reaches it. The shares stay in the volume.",
	Run: upload,
}

func upload(ctx context.Context, e Env, rec *report.Recorder) error {
	if len(e.Volume.Accounts) == 0 {
		return Skip("the volume's manifest carries no accounts")
	}
	probe := e.probe()
	defer probe.Close()
	index, token, err := quotaFree(ctx, e, probe)
	if err != nil {
		return err
	}
	rec.Value(valUploadAccount, float64(index), "account")
	rec.Value(valClientManifestFiles, clientManifestFiles, "files")
	rec.Value(valClientBatchFiles, clientBatchFiles, "files")
	c := e.client(rec, 0)
	defer c.Close()
	fill := e.scaledFiles(e.Plan.FileCap)

	created := 0
	n, err := fillOneByOne(ctx, e, rec, c, probe, token, fill)
	created += n
	if err == nil {
		n, err = fillBatches(ctx, e, rec, c, probe, token, fill)
		created += n
	}
	if err == nil {
		n, err = fillPending(ctx, e, rec, c, probe, token)
		created += n
	}
	if err == nil {
		n, err = createAcross(ctx, e, rec)
		created += n
	}
	rec.Value(valSharesCreated, float64(created), "shares")
	return err
}

// scaledFiles is n files at scale 1, otherwise n times the scale and at
// least uploadLeast, never more than n.
func (e Env) scaledFiles(n int) int {
	if e.Scale <= 0 || e.Scale >= 1 {
		return n
	}
	return min(n, max(uploadLeast, int(float64(n)*e.Scale)))
}

// reserved is the create body of a share for files files with their bytes
// reserved and no manifest, as the client creates one past its manifest
// bound.
func reserved(name string, files int) map[string]any {
	return map[string]any{"name": name, "reserveBytes": files * uploadFileSize}
}

// fillOneByOne creates a share as the client does for a big folder and
// fills it with fill files through the per-file route, then sends one more
// when the fill reached the cap. It answers the shares it created.
func fillOneByOne(ctx context.Context, e Env, rec *report.Recorder, c, probe *target.Client, token string, fill int) (int, error) {
	id, err := createShare(ctx, c, opCreateShare, token, reserved("loadrig upload", fill))
	if err != nil || id == "" {
		return 0, createFailed("the share to fill", err)
	}
	uploaded := 0
	began := time.Now()
	f := 0
	if err := repeat(ctx, e, count(fill), func() error {
		f++
		ok, err := putFile(ctx, c, uploadWindowOp(f), token, id, fileRel(f), f)
		if ok {
			uploaded++
		}
		return err
	}); err != nil {
		return 1, err
	}
	rec.Value(valFilesUploaded, float64(uploaded), "files")
	rec.Value(valFillTook, time.Since(began).Seconds(), "s")
	if fill == e.Plan.FileCap {
		over := e.Plan.FileCap + 1
		status := 0
		err := c.DoHeader(ctx, opPastCap, http.MethodPut, filePath(id, fileRel(over)), token, uploadHeader(id, over), bytes.NewReader(fileBytes(over)), func(r *http.Response) error {
			status = r.StatusCode
			return nil
		})
		switch {
		case err != nil && !answering(e.Target):
			return 1, errStopped
		case err != nil:
			rec.NotAvailable(valPastCap, "the request for file "+strconv.Itoa(over)+" failed: "+err.Error())
		default:
			rec.Value(valPastCap, float64(status), "status")
			if status == http.StatusCreated {
				uploaded++
			}
		}
	} else {
		rec.NotAvailable(valPastCap, fmt.Sprintf("the fill stopped at %d files of the cap of %d at scale %g", fill, e.Plan.FileCap, e.Scale))
	}
	if err := shareCounts(ctx, rec, probe, valShareFiles, id, token, uploaded); err != nil {
		return 1, err
	}
	growth(rec)
	return 1, nil
}

// fillBatches creates a share as fillOneByOne does and fills it with fill
// files through the batch route, clientBatchFiles to a request.
func fillBatches(ctx context.Context, e Env, rec *report.Recorder, c, probe *target.Client, token string, fill int) (int, error) {
	id, err := createShare(ctx, c, opCreateBatchShare, token, reserved("loadrig batches", fill))
	if err != nil || id == "" {
		return 0, createFailed("the share to fill with batches", err)
	}
	uploaded := 0
	began := time.Now()
	next := 1
	if err := repeat(ctx, e, count((fill+clientBatchFiles-1)/clientBatchFiles), func() error {
		first, last := next, min(fill, next+clientBatchFiles-1)
		next = last + 1
		n, err := putBatch(ctx, c, batchWindowOp(first), token, id, first, last)
		uploaded += n
		return err
	}); err != nil {
		return 1, err
	}
	rec.Value(valBatchFilesUploaded, float64(uploaded), "files")
	rec.Value(valBatchTook, time.Since(began).Seconds(), "s")
	return 1, shareCounts(ctx, rec, probe, valBatchShareFiles, id, token, uploaded)
}

// fillPending creates a share with a manifest of the client's bound of
// files, scaled like the fill, and completes each pending file with one PUT.
func fillPending(ctx context.Context, e Env, rec *report.Recorder, c, probe *target.Client, token string) (int, error) {
	n := e.scaledFiles(clientManifestFiles)
	files := make([]map[string]any, n)
	for f := 1; f <= n; f++ {
		files[f-1] = map[string]any{"path": fileRel(f), "size": uploadFileSize}
	}
	body := reserved("loadrig manifest", n)
	body["files"] = files
	id, err := createShare(ctx, c, opCreateWithManifest, token, body)
	if err != nil || id == "" {
		return 0, createFailed("the share with a manifest", err)
	}
	rec.Value(valManifestFiles, float64(n), "files")
	uploaded := 0
	f := 0
	if err := repeat(ctx, e, count(n), func() error {
		f++
		ok, err := putFile(ctx, c, pendingWindowOp(f), token, id, fileRel(f), f)
		if ok {
			uploaded++
		}
		return err
	}); err != nil {
		return 1, err
	}
	rec.Value(valPendingUploaded, float64(uploaded), "files")
	return 1, shareCounts(ctx, rec, probe, valManifestShareFiles, id, token, n)
}

// createFailed is the error of a share the scenario needs and could not
// create.
func createFailed(what string, err error) error {
	if err != nil {
		return fmt.Errorf("creating %s: %w", what, err)
	}
	return fmt.Errorf("the server's limits refused %s", what)
}

// shareCounts reads share id back and records its file count under name;
// a count other than want is wrong.
func shareCounts(ctx context.Context, rec *report.Recorder, probe *target.Client, name, id, token string, want int) error {
	s, err := readShare(ctx, probe, "probe", id, token)
	if err != nil {
		return fmt.Errorf("reading share %s: %w", id, err)
	}
	rec.Value(name, float64(s.FileCount), "files")
	if s.FileCount != want {
		rec.Wrong(name, fmt.Sprintf("the share should hold %d files, it counts %d", want, s.FileCount))
	}
	return nil
}

// quotaFree is the first account from uploadAccount on, then the ones
// before it, whose usage names no quota, with its token.
func quotaFree(ctx context.Context, e Env, probe *target.Client) (int, string, error) {
	tokens := map[string]string{}
	for _, a := range e.Volume.Accounts {
		tokens[a.Name] = a.Token
	}
	for k := range e.Plan.Accounts {
		i := (uploadAccount + k) % e.Plan.Accounts
		token := tokens[e.Plan.Account(i)]
		if token == "" {
			continue
		}
		var usage struct {
			QuotaBytes int64 `json:"quotaBytes"`
		}
		if err := probe.Do(ctx, "probe", http.MethodGet, "/api/me", token, nil, func(r *http.Response) error {
			return decodeOK(r, &usage)
		}); err != nil {
			return 0, "", fmt.Errorf("reading %s's usage: %w", e.Plan.Account(i), err)
		}
		if usage.QuotaBytes == 0 {
			return i, token, nil
		}
	}
	return 0, "", Skip("every account of the volume has a quota")
}

// createShare creates a share from body and answers its id, or "" when the
// server's limits refused it.
func createShare(ctx context.Context, c *target.Client, op, token string, body map[string]any) (string, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	var out struct {
		ID string `json:"id"`
	}
	err = c.Do(ctx, op, http.MethodPost, "/api/shares", token, bytes.NewReader(b), func(r *http.Response) error {
		if refusedByLimit(r) {
			return nil
		}
		if r.StatusCode != http.StatusCreated {
			return fmt.Errorf("answered %d", r.StatusCode)
		}
		if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
			return fmt.Errorf("body: %w", err)
		}
		if out.ID == "" {
			return fmt.Errorf("a created share without an id")
		}
		return nil
	})
	return out.ID, err
}

// putFile uploads file f as rel into share id whole, in one ranged PUT,
// which commits it: the answer must be 201 naming rel at its size, or a
// refusal by the server's limits. ok reports a committed file.
func putFile(ctx context.Context, c *target.Client, op, token, id, rel string, f int) (ok bool, err error) {
	err = c.DoHeader(ctx, op, http.MethodPut, filePath(id, rel), token, uploadHeader(id, f), bytes.NewReader(fileBytes(f)), func(r *http.Response) error {
		if refusedByLimit(r) {
			return nil
		}
		if r.StatusCode != http.StatusCreated {
			return fmt.Errorf("answered %d", r.StatusCode)
		}
		var out struct {
			Path string `json:"path"`
			Size int64  `json:"size"`
		}
		if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
			return fmt.Errorf("body: %w", err)
		}
		if out.Path != rel || out.Size != uploadFileSize {
			return fmt.Errorf("uploaded %s of %d bytes, committed %s of %d", rel, uploadFileSize, out.Path, out.Size)
		}
		ok = true
		return nil
	})
	return ok, err
}

// putBatch uploads files first to last into share id as one tar request to
// the batch route: the answer must commit every one of them, or be a
// refusal by the server's limits. It answers how many committed.
func putBatch(ctx context.Context, c *target.Client, op, token, id string, first, last int) (int, error) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for f := first; f <= last; f++ {
		if err := tw.WriteHeader(&tar.Header{Name: fileRel(f), Mode: 0o644, Size: uploadFileSize, Typeflag: tar.TypeReg}); err != nil {
			return 0, err
		}
		if _, err := tw.Write(fileBytes(f)); err != nil {
			return 0, err
		}
	}
	if err := tw.Close(); err != nil {
		return 0, err
	}
	committed := 0
	header := http.Header{"Content-Type": {"application/x-tar"}}
	err := c.DoHeader(ctx, op, http.MethodPost, "/api/shares/"+id+"/batch", token, header, &b, func(r *http.Response) error {
		if refusedByLimit(r) {
			return nil
		}
		var out struct {
			Committed int    `json:"committed"`
			Error     string `json:"error"`
		}
		if err := decodeOK(r, &out); err != nil {
			return err
		}
		committed = out.Committed
		if want := last - first + 1; out.Committed != want || out.Error != "" {
			return fmt.Errorf("a batch of %d files committed %d (%q)", want, out.Committed, out.Error)
		}
		return nil
	})
	return committed, err
}

func filePath(id, rel string) string { return "/api/shares/" + id + "/files/" + rel }

// uploadHeader is the headers of file f's one ranged PUT: the whole file
// as one range, under a session of its own.
func uploadHeader(id string, f int) http.Header {
	return http.Header{
		"Upload-Session": {fmt.Sprintf("loadrig-%s-%06d", id, f)},
		"Upload-Total":   {strconv.Itoa(uploadFileSize)},
		"Upload-Range":   {"0-" + strconv.Itoa(uploadFileSize)},
	}
}

// fileRel is file f's relative path: a folder per window of files.
func fileRel(f int) string {
	return fmt.Sprintf("set%03d/file_%06d.txt", (f-1)/uploadWindow, f)
}

// fileBytes is file f's content: uploadFileSize bytes of text no other
// file shares.
func fileBytes(f int) []byte {
	b := make([]byte, uploadFileSize)
	for i := range b {
		b[i] = 'a' + byte((f+i)%26)
	}
	copy(b, fmt.Sprintf("loadrig file %d\n", f))
	b[len(b)-1] = '\n'
	return b
}

// growth reports the per-file median of the last window over the first's,
// once the fill has more than one window.
func growth(rec *report.Recorder) {
	var first, last report.Op
	windows := 0
	for _, o := range rec.Scenario("", 0).Ops {
		if o.Name == uploadWindowOp(1+windows*uploadWindow) && o.ByAnswer["201"] > 0 {
			if windows == 0 {
				first = o
			}
			last = o
			windows++
		}
	}
	if windows < 2 || first.P50 <= 0 {
		rec.NotAvailable(valGrowth, "the fill holds one window of files")
		return
	}
	rec.Value(valGrowth, float64(last.P50)/float64(first.P50), "x")
}

// createAcross creates one-file shares across every account of the volume
// for the scaled createHold, each worker moving to another account every
// round, and answers how many it created. A share the server's limits
// refuse is an answer; one created is uploaded its file.
func createAcross(ctx context.Context, e Env, rec *report.Recorder) (int, error) {
	var accts []volume.Account
	for _, a := range e.Volume.Accounts {
		if a.Token != "" {
			accts = append(accts, a)
		}
	}
	workers := min(createWorkers, len(accts))
	rec.Value(valCreateAccounts, float64(len(accts)), "accounts")
	rec.Value(valCreateBurst, createBurst, "shares")
	rec.Value(valCreatePerHour, createPerHour, "shares")
	manifest := map[string]any{"name": "loadrig one file", "reserveBytes": uploadFileSize,
		"files": []map[string]any{{"path": oneFileName, "size": uploadFileSize}}}
	var created atomic.Int64
	rounds := make([]int, workers)
	began := time.Now()
	err := parallel(ctx, e, rec, workers, until(began.Add(e.hold(createHold))), func(w int, c *target.Client) error {
		a := accts[(w+rounds[w]*workers)%len(accts)]
		rounds[w]++
		id, err := createShare(ctx, c, opCreateOne, a.Token, manifest)
		if err != nil || id == "" {
			return err
		}
		created.Add(1)
		_, err = putFile(ctx, c, opUploadOne, a.Token, id, oneFileName, 0)
		return err
	})
	wall := time.Since(began)
	n := int(created.Load())
	rec.Value(valCreateRate, float64(n)/wall.Seconds(), "shares/s")
	refused := 0
	for _, o := range rec.Scenario("", 0).Ops {
		if o.Name == opCreateOne {
			refused = refusals(o)
		}
	}
	rec.Value(valCreateRefusals, float64(refused), "answers")
	return n, err
}
