package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hyperdrop/server/internal/sharefs"
)

// swapVersion is file i's content in version v of TestAReaderNeverPairsARowWithOtherBytes:
// the two versions differ in length as well as bytes, so a mismatched row
// shows in the entity tag and the type sniffed from either is text.
func swapVersion(v, i int) string {
	if v == 0 {
		return strings.Repeat("a", 1000+i)
	}
	return strings.Repeat("b", 3000+7*i)
}

// publishVersion stages every file of names at version v into one publish
// of share id and commits it.
func publishVersion(t *testing.T, h http.Handler, id string, names []string, v int) {
	t.Helper()
	pid := openPublish(t, h, testToken, id)
	for i, rel := range names {
		stageFile(t, h, id, pid, rel, swapVersion(v, i))
	}
	body, _ := json.Marshal(map[string]any{"files": names})
	if rec := commitPublish(t, h, id, pid, string(body)); rec.Code != 200 {
		t.Fatalf("commit version %d: %d %s", v, rec.Code, rec.Body)
	}
}

// A visitor's response is always one version: the entity tag (the row's
// hash) and the length name the very bytes in the body, on /view, /download,
// /site and a file link's View and Download alike, while a fixed number of commits swap twenty files
// between two versions underneath eight readers. The count, not a clock,
// bounds the run, so a slow machine runs it longer rather than thinner.
func TestAReaderNeverPairsARowWithOtherBytes(t *testing.T) {
	h, _ := publishAPI(t)
	id := createShare(t, h, "swap")
	names := make([]string, 20)
	for i := range names {
		names[i] = fmt.Sprintf("f%02d.txt", i)
		uploadGetSlug(t, h, id, names[i], swapVersion(0, i))
	}
	slugs := readListed(t, h, id).slugs()
	var paths []string
	for _, rel := range names {
		key := mintFileKey(t, h, testToken, id, slugs[rel])
		paths = append(paths, "/view/"+id+"/"+slugs[rel], "/download/"+id+"/"+slugs[rel], "/site/"+id+"/"+rel,
			"/f/"+key, "/f/"+key+"/download")
	}

	const commits = 6
	var stop atomic.Bool
	var checked, mismatched atomic.Int64
	var wg sync.WaitGroup
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			for n := r; !stop.Load(); n++ {
				p := paths[n%len(paths)]
				rec := req(t, h, "GET", "files.share.example.com", p)
				if rec.Code != 200 {
					t.Errorf("%s answered %d", p, rec.Code)
					return
				}
				body := rec.Body.String()
				etag := rec.Header().Get("ETag")
				length := rec.Header().Get("Content-Length")
				checked.Add(1)
				if etag != `"`+sha(body)+`"` || length != strconv.Itoa(len(body)) {
					if mismatched.Add(1) <= 3 {
						t.Errorf("%s: ETag %s, Content-Length %s, for a body of %d bytes (sha %s)",
							p, etag, length, len(body), sha(body)[:12])
					}
				}
			}
		}(r)
	}
	for i := 0; i < commits; i++ {
		publishVersion(t, h, id, names, 1-i%2)
	}
	stop.Store(true)
	wg.Wait()
	if mismatched.Load() > 0 {
		t.Fatalf("%d of %d responses paired a row with another version's bytes over %d commits",
			mismatched.Load(), checked.Load(), commits)
	}
	if checked.Load() == 0 {
		t.Fatalf("nothing was exercised: %d responses over %d commits", checked.Load(), commits)
	}
}

// A visitor's read waits for no lock an unrelated commit holds: while a
// plain ranged commit holds the share lock (its row still being written,
// standing in for a long hash) and a publish commit naming the same path
// waits behind it, the share's files still answer at once.
func TestAReaderDoesNotWaitBehindAnUnrelatedCommit(t *testing.T) {
	h, b := publishAPI(t)
	id := createShare(t, h, "busy")
	slug := uploadGetSlug(t, h, id, "page.txt", "served throughout")
	uploadGetSlug(t, h, id, "big.bin", "the stored big file")

	pid := openPublish(t, h, testToken, id)
	stageFile(t, h, id, pid, "big.bin", "published big file")
	big := []byte(strings.Repeat("B", 1<<16))
	if _, err := b.FS.WriteRange(id, "big.bin", strings.NewReader(string(big)),
		sharefs.Range{Start: 0, End: int64(len(big))}, int64(len(big)), "plain-session", nil); err != nil {
		t.Fatal(err)
	}
	holding, release := make(chan struct{}), make(chan struct{})
	plainDone := make(chan error, 1)
	go func() {
		_, err := b.FS.CommitRanged(id, "big.bin", int64(len(big)), "plain-session", func(sharefs.Committed) error {
			close(holding)
			<-release
			return errors.New("the row refuses the bytes")
		})
		plainDone <- err
	}()
	<-holding

	publishDone := make(chan int, 1)
	go func() {
		rec := doReq(t, h, "POST", "/api/shares/"+id+"/publishes/"+pid+"/commit", testToken, `{"files":["big.bin"]}`)
		publishDone <- rec.Code
	}()
	time.Sleep(50 * time.Millisecond)
	select {
	case code := <-publishDone:
		close(release)
		t.Fatalf("the publish commit did not wait for the plain commit of its path: %d", code)
	default:
	}

	for _, p := range []string{"/view/" + id + "/" + slug, "/download/" + id + "/" + slug, "/site/" + id + "/page.txt"} {
		start := time.Now()
		rec := req(t, h, "GET", "files.share.example.com", p)
		if took := time.Since(start); took > 100*time.Millisecond {
			close(release)
			t.Fatalf("%s took %v behind an unrelated commit", p, took)
		}
		if rec.Code != 200 || rec.Body.String() != "served throughout" {
			close(release)
			t.Fatalf("%s = %d %q", p, rec.Code, rec.Body)
		}
	}

	close(release)
	if err := <-plainDone; err == nil {
		t.Fatal("the plain commit's refused row committed")
	}
	if code := <-publishDone; code != 200 {
		t.Fatalf("the publish commit after the plain one: %d", code)
	}
	if got, _ := publishedBytes(t, b, id, "big.bin"); got != "published big file" {
		t.Fatalf("big.bin after both commits = %q", got)
	}
}

// A download opened before a commit streams the version it opened to the
// end, under that version's entity tag, and the commit does not wait for
// the transfer.
func TestASlowDownloadFinishesOnItsVersion(t *testing.T) {
	h, _ := publishAPI(t)
	id := createShare(t, h, "slow")
	old := strings.Repeat("o", 16<<20)
	slug := uploadGetSlug(t, h, id, "movie.bin", old)

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	r, err := http.NewRequest("GET", srv.URL+"/download/"+id+"/"+slug, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "files.share.example.com"
	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("download = %d", resp.StatusCode)
	}
	head := make([]byte, 1<<20)
	if _, err := io.ReadFull(resp.Body, head); err != nil {
		t.Fatal(err)
	}

	pid := openPublish(t, h, testToken, id)
	stageFile(t, h, id, pid, "movie.bin", "the new, shorter version")
	committed := make(chan int, 1)
	go func() { committed <- commitPublish(t, h, id, pid, `{"files":["movie.bin"]}`).Code }()
	select {
	case code := <-committed:
		if code != 200 {
			t.Fatalf("commit during the download: %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the commit waited for a download in flight")
	}
	if rec := req(t, h, "GET", "files.share.example.com", "/download/"+id+"/"+slug); rec.Body.String() != "the new, shorter version" {
		t.Fatalf("a download after the commit = %q", rec.Body)
	}

	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	body := string(head) + string(rest)
	if body != old {
		t.Fatalf("the download in flight ended with %d bytes, not the %d it opened", len(body), len(old))
	}
	if got := resp.Header.Get("ETag"); got != `"`+sha(old)+`"` {
		t.Fatalf("the download in flight carried ETag %s", got)
	}
}

// A publish that deletes the file a share's poster was taken from takes the
// poster off the public card: the check that the poster's entry still
// resolves runs on every read.
func TestAPublishDeletingThePostersFileWithholdsThePoster(t *testing.T) {
	h, _ := publishAPI(t)
	id := createShare(t, h, "clip")
	uploadGetSlug(t, h, id, "clip.mp4", "video bytes")
	if code := putPoster(t, h, id, posterJPEG(t, "frame")); code != http.StatusNoContent {
		t.Fatalf("PUT poster = %d", code)
	}
	if rec := doReq(t, h, "GET", "/card/"+id+"/poster.jpg", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("poster with its file present = %d, want 200", rec.Code)
	}
	pid := openPublish(t, h, testToken, id)
	stageFile(t, h, id, pid, "note.txt", "the clip is gone")
	if rec := commitPublish(t, h, id, pid, `{"files":["note.txt"],"delete":["clip.mp4"]}`); rec.Code != 200 {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/card/"+id+"/poster.jpg", "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("poster after a publish deleted its file = %d, want 404", rec.Code)
	}
}

// The poster's check and its read run under the share's swap lock: a read
// arriving while a commit holds the lock waits for it, then answers as the
// commit left the share, here with the poster's file deleted.
func TestThePosterReadWaitsForACommit(t *testing.T) {
	h, b := publishAPI(t)
	id := createShare(t, h, "clip")
	uploadGetSlug(t, h, id, "clip.mp4", "video bytes")
	if code := putPoster(t, h, id, posterJPEG(t, "frame")); code != http.StatusNoContent {
		t.Fatalf("PUT poster = %d", code)
	}
	answered := make(chan int, 1)
	err := b.FS.WithSwap(id, nil, nil, func() error {
		go func() { answered <- doReq(t, h, "GET", "/card/"+id+"/poster.jpg", "", "").Code }()
		select {
		case code := <-answered:
			return fmt.Errorf("the poster answered %d while a commit held the swap lock", code)
		case <-time.After(100 * time.Millisecond):
		}
		_, _, err := b.DB.RemoveFiles(id, []string{"clip.mp4"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if code := <-answered; code != http.StatusNotFound {
		t.Fatalf("the poster read after the commit deleted its file = %d, want 404", code)
	}
}
