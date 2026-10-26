package api

import (
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type inboxHeldBody struct {
	io.Reader
	entered chan<- struct{}
	release <-chan struct{}
	once    sync.Once
}

func (b *inboxHeldBody) Read(p []byte) (int, error) {
	b.once.Do(func() { b.entered <- struct{}{}; <-b.release })
	return b.Reader.Read(p)
}

func TestConcurrentInboxCommitsRespectFileCap(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		files, bytes, winners int
	}{
		{"one file", 1, 0, 1}, {"two files", 2, 0, 2}, {"one byte", 0, 1, 1}, {"two bytes", 0, 2, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := testBackend(t)
			h := New(b, "test", testDomain(t), nil)
			id := createInbox(t, h, fmt.Sprintf(`{"name":"inbox","receive":true,"maxFiles":%d,"maxBytes":%d}`, tc.files, tc.bytes))
			entered := make(chan struct{}, 2)
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			var wg sync.WaitGroup
			defer func() { unblock(); wg.Wait() }()
			done := make(chan struct{}, 2)
			results := make([]*httptest.ResponseRecorder, 2)
			for i, name := range []string{"a.txt", "b.txt"} {
				wg.Add(1)
				go func(i int, name string) {
					defer wg.Done()
					req := httptest.NewRequest("PUT", "/receive/"+id+"/files/"+name, &inboxHeldBody{Reader: strings.NewReader("x"), entered: entered, release: release})
					req.ContentLength = 1
					rec := httptest.NewRecorder()
					h.ServeHTTP(rec, req)
					results[i] = rec
					done <- struct{}{}
				}(i, name)
				// The next request sees this pending declaration. It must still
				// be admitted: an upload whose body stalls cannot reserve a slot.
				select {
				case <-entered:
				case <-done:
					t.Fatal("pending upload caused early rejection")
				case <-time.After(5 * time.Second):
					t.Fatal("both declared uploads must reach body reads")
				}
			}
			unblock()
			for range 2 {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("upload did not finish")
				}
			}
			winners := 0
			for i, rec := range results {
				if rec.Code == 201 {
					winners++
					continue
				}
				if rec.Code != 413 || !strings.Contains(rec.Body.String(), `"code":"receive-full"`) {
					t.Errorf("upload %d=%d %s", i, rec.Code, rec.Body)
				}
				name := []string{"a.txt", "b.txt"}[i]
				if f, _, err := b.FS.Open(id, name); err == nil {
					f.Close()
					t.Error("refused file remains on disk")
				}
				if size, err := b.FS.PartSize(id, name); err != nil || size != 0 {
					t.Errorf("refused staging=%d %v", size, err)
				}
			}
			sh, err := b.DB.Share(id)
			if err != nil {
				t.Fatal(err)
			}
			if winners != tc.winners || sh.Committed != tc.winners || len(sh.Files) != tc.winners {
				t.Fatalf("want=%d winners=%d committed=%d rows=%d", tc.winners, winners, sh.Committed, len(sh.Files))
			}
		})
	}
}
