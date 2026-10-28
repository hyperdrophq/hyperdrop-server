package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

const (
	mib int64 = 1 << 20
	gib int64 = 1 << 30
)

// dripBody sends one byte and then blocks until stop closes, the way a
// sender dripping a large declared body at the rate floor looks to the
// handler for as long as it keeps going.
type dripBody struct {
	sent    bool
	once    sync.Once
	dripped chan<- struct{}
	stop    <-chan struct{}
}

func (d *dripBody) Read(p []byte) (int, error) {
	if !d.sent {
		d.sent = true
		p[0] = 'x'
		return 1, nil
	}
	d.once.Do(func() { d.dripped <- struct{}{} })
	<-d.stop
	return 0, io.ErrUnexpectedEOF
}

// drip is one dripping request in flight.
type drip struct {
	stop chan struct{}
	done chan *httptest.ResponseRecorder
}

// startDrip serves req, whose body is a dripBody it builds, and answers once
// the handler has either read the first byte and is waiting for more (true)
// or has answered without waiting (false, with its answer in rec).
func startDrip(t *testing.T, h http.Handler, method, path string, size int64, prep func(*http.Request)) (d *drip, dripping bool, rec *httptest.ResponseRecorder) {
	t.Helper()
	dripped := make(chan struct{}, 1)
	d = &drip{stop: make(chan struct{}), done: make(chan *httptest.ResponseRecorder, 1)}
	req := httptest.NewRequest(method, path, &dripBody{dripped: dripped, stop: d.stop})
	req.ContentLength = size
	if prep != nil {
		prep(req)
	}
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		d.done <- rec
	}()
	t.Cleanup(d.end)
	select {
	case <-dripped:
		return d, true, nil
	case rec := <-d.done:
		d.done <- rec
		return d, false, rec
	}
}

// noSpaceWithoutFigures fails the test unless rec is a 507 no-space whose
// body names no figure.
func noSpaceWithoutFigures(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != 507 || errCode(t, rec.Body.String()) != "no-space" {
		t.Fatalf("%s = %d %s, want 507 no-space", what, rec.Code, rec.Body)
	}
	if strings.ContainsAny(rec.Body.String(), "0123456789") {
		t.Fatalf("%s names a figure: %s", what, rec.Body)
	}
}

// rangedDrip drips a signed-in chunk of the whole of size bytes into share.
func rangedDrip(t *testing.T, h http.Handler, token, share, name string, size int64) (*drip, bool, *httptest.ResponseRecorder) {
	t.Helper()
	return startDrip(t, h, "PUT", "/api/shares/"+share+"/files/"+name, size, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Upload-Session", "test-session")
		r.Header.Set("Upload-Range", "0-"+strconv.FormatInt(size, 10))
		r.Header.Set("Upload-Total", strconv.FormatInt(size, 10))
	})
}

// end stops the drip and waits for its request to answer.
func (d *drip) end() {
	select {
	case <-d.stop:
		return
	default:
	}
	close(d.stop)
	<-d.done
}

func inboxDrip(t *testing.T, h http.Handler, id, name, addr string, size int64) (*drip, bool, *httptest.ResponseRecorder) {
	t.Helper()
	return startDrip(t, h, "PUT", "/receive/"+id+"/files/"+name, size, func(r *http.Request) { r.RemoteAddr = addr })
}

// diskOf gives the backend a fake disk with free bytes free of 100 GiB and
// the flat 1 GiB reserve.
func diskOf(b Backend, free int64) {
	b.FS.ReservePercent = sharefs.FlatReserve
	b.FS.DiskSpace = func(string) (int64, int64, error) { return free, 100 * gib, nil }
}

func batchOf(t *testing.T, name string, size int64) []byte {
	t.Helper()
	return tarOf(t, map[string]string{name: strings.Repeat("x", int(size))}, nil)
}

// A stranger's upload declaring nearly the whole disk and dripping its body
// holds one window, so the owner's batch, a second inbox's upload and a new
// share's reservation all go ahead beside it.
func TestADrippingInboxUploadDoesNotBlockOtherWrites(t *testing.T) {
	b := testBackend(t)
	diskOf(b, 10*gib) // 9 GiB usable
	h := New(b, "test", testDomain(t), nil)
	first := createInbox(t, h, `{"name":"first","receive":true}`)
	second := createInbox(t, h, `{"name":"second","receive":true}`)
	share := createShare(t, h, "own")
	if _, dripping, rec := inboxDrip(t, h, first, "big.bin", "192.0.2.1:1234", 9*gib); !dripping {
		t.Fatalf("the 9 GiB upload answered %d before its body", rec.Code)
	}
	if rec := postBatch(t, h, share, testToken, batchOf(t, "own.bin", 100*mib), ""); rec.Code != 200 {
		t.Fatalf("owner batch of 100 MiB = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PUT", "/receive/"+second+"/files/note.txt", "", "hello"); rec.Code != 201 {
		t.Fatalf("second inbox upload = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "POST", "/api/shares", testToken, fmt.Sprintf(`{"name":"r","reserveBytes":%d}`, 100*mib)); rec.Code != 201 {
		t.Fatalf("a 100 MiB reservation = %d %s", rec.Code, rec.Body)
	}
}

// A signed-in chunk declaring nearly the whole disk holds one window too.
func TestADrippingRangedChunkDoesNotBlockOtherWrites(t *testing.T) {
	b := testBackend(t)
	diskOf(b, 10*gib)
	h := New(b, "test", testDomain(t), nil)
	big := createShare(t, h, "big")
	other := createShare(t, h, "other")
	inbox := createInbox(t, h, `{"name":"inbox","receive":true}`)
	if _, dripping, rec := rangedDrip(t, h, testToken, big, "big.bin", 9*gib); !dripping {
		t.Fatalf("the 9 GiB chunk answered %d before its body", rec.Code)
	}
	if rec := postBatch(t, h, other, testToken, batchOf(t, "own.bin", 100*mib), ""); rec.Code != 200 {
		t.Fatalf("owner batch of 100 MiB = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PUT", "/receive/"+inbox+"/files/note.txt", "", "hello"); rec.Code != 201 {
		t.Fatalf("inbox upload = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "POST", "/api/shares", testToken, fmt.Sprintf(`{"name":"r","reserveBytes":%d}`, 100*mib)); rec.Code != 201 {
		t.Fatalf("a 100 MiB reservation = %d %s", rec.Code, rec.Body)
	}
}

// On a small disk, more dripping strangers than the usable space has
// windows take at most half of it: the owner's batch of that half goes
// ahead, and a reservation gets exactly what is left, never the system
// reserve.
func TestDrippingStrangersTakeAtMostHalfASmallDisk(t *testing.T) {
	b := testBackend(t)
	diskOf(b, 1*gib+256*mib) // 256 MiB usable, so four 64 MiB windows
	h := New(b, "test", testDomain(t), nil)
	inboxes := []string{
		createInbox(t, h, `{"name":"a","receive":true}`),
		createInbox(t, h, `{"name":"b","receive":true}`),
	}
	share := createShare(t, h, "own")
	admitted := 0
	for i := 0; i < 10; i++ {
		_, dripping, rec := inboxDrip(t, h, inboxes[i%2], fmt.Sprintf("f%d.bin", i), fmt.Sprintf("192.0.2.%d:1234", i+1), 100*mib)
		if dripping {
			admitted++
			continue
		}
		noSpaceWithoutFigures(t, fmt.Sprintf("drip %d", i), rec)
	}
	if admitted != 2 {
		t.Fatalf("%d strangers hold a window, want the 2 that fit in half of 256 MiB", admitted)
	}
	if rec := postBatch(t, h, share, testToken, batchOf(t, "own.bin", 128*mib), ""); rec.Code != 200 {
		t.Fatalf("owner batch of half the usable space = %d %s", rec.Code, rec.Body)
	}
	// Each stranger has landed one byte of its window, so what is left is
	// the other half and those two bytes.
	left := 128*mib + 2
	rec := doReq(t, h, "POST", "/api/shares", testToken, fmt.Sprintf(`{"name":"r","reserveBytes":%d}`, left+1))
	if rec.Code != 507 || errCode(t, rec.Body.String()) != "no-space" {
		t.Fatalf("a reservation into the system reserve = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "POST", "/api/shares", testToken, fmt.Sprintf(`{"name":"r","reserveBytes":%d}`, left)); rec.Code != 201 {
		t.Fatalf("a reservation of what is left = %d %s", rec.Code, rec.Body)
	}
}

// failBody fails the test if the handler reads it.
type failBody struct{ read bool }

func (f *failBody) Read([]byte) (int, error) { f.read = true; return 0, io.ErrUnexpectedEOF }

// An inbox upload past the owner's quota is refused before its body: no
// part, no pending row, and nothing in the refusal about the account.
func TestAnInboxUploadPastTheOwnersQuotaIsRefusedBeforeItsBody(t *testing.T) {
	b := testBackend(t)
	h := New(b, "test", testDomain(t), nil)
	token := seedUser(t, b.DB, "bob")
	quota := mib
	if _, err := b.DB.UpdateUser("bob", metadb.Settings{QuotaBytes: &quota}); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, h, "POST", "/api/shares", token, `{"name":"inbox","receive":true}`)
	var created struct{ ID string }
	unmarshal(t, rec, &created)
	body := &failBody{}
	req := httptest.NewRequest("PUT", "/receive/"+created.ID+"/files/big.bin", body)
	req.ContentLength = 2 * mib
	got := httptest.NewRecorder()
	h.ServeHTTP(got, req)
	if got.Code != 507 || errCode(t, got.Body.String()) != "quota" {
		t.Fatalf("upload past the quota = %d %s, want 507 quota", got.Code, got.Body)
	}
	if body.read {
		t.Fatal("the body was read")
	}
	if strings.Contains(got.Body.String(), strconv.FormatInt(mib, 10)) {
		t.Fatalf("the refusal names the account's quota: %s", got.Body)
	}
	if n, err := b.FS.PartSize(created.ID, "big.bin"); err != nil || n != 0 {
		t.Fatalf("a part was staged: %d %v", n, err)
	}
	if _, err := b.DB.File(created.ID, "big.bin"); !errors.Is(err, metadb.ErrNotFound) {
		t.Fatalf("a row was declared: %v", err)
	}
	if rec := doReq(t, h, "PUT", "/receive/"+created.ID+"/files/small.txt", "", "hello"); rec.Code != 201 {
		t.Fatalf("an upload inside the quota = %d %s", rec.Code, rec.Body)
	}
}

// One account's whole-disk reservations, one after another, hold at most
// half the usable space: another account still reserves and writes the
// other half.
func TestRepeatedWholeDiskReservationsLeaveOthersHalf(t *testing.T) {
	b := testBackend(t)
	diskOf(b, 10*gib) // 9 GiB usable
	h := New(b, "test", testDomain(t), nil)
	bob := seedUser(t, b.DB, "bob")
	whole := fmt.Sprintf(`{"name":"r","reserveBytes":%d}`, 9*gib)
	if rec := doReq(t, h, "POST", "/api/shares", bob, whole); rec.Code != 201 {
		t.Fatalf("the first whole-disk reservation = %d %s", rec.Code, rec.Body)
	}
	for i := 0; i < 3; i++ {
		noSpaceWithoutFigures(t, "another whole-disk reservation", doReq(t, h, "POST", "/api/shares", bob, whole))
	}
	if rec := doReq(t, h, "POST", "/api/shares", bob, fmt.Sprintf(`{"name":"r","reserveBytes":%d}`, 4*gib)); rec.Code != 201 {
		t.Fatalf("a reservation past bob's half is clamped, not refused = %d %s", rec.Code, rec.Body)
	}
	share := createShareAs(t, h, testToken, fmt.Sprintf(`{"name":"mine","reserveBytes":%d}`, 9*gib/2))
	if rec := postBatch(t, h, share, testToken, batchOf(t, "own.bin", 100*mib), ""); rec.Code != 200 {
		t.Fatalf("another account's batch into its reservation = %d %s", rec.Code, rec.Body)
	}
}

// Many dripping chunks from one account, across its shares, hold at most
// half the usable space; the others are refused, and another account's
// batch of the other half goes ahead.
func TestOneAccountsDrippingChunksHoldAtMostHalf(t *testing.T) {
	b := testBackend(t)
	diskOf(b, 1*gib+256*mib) // 256 MiB usable, so two 64 MiB windows per account
	h := New(b, "test", testDomain(t), nil)
	bob := seedUser(t, b.DB, "bob")
	admitted := 0
	for i := 0; i < 5; i++ {
		share := createShareAs(t, h, bob, fmt.Sprintf(`{"name":"s%d"}`, i))
		_, dripping, rec := rangedDrip(t, h, bob, share, "big.bin", 100*mib)
		if dripping {
			admitted++
			continue
		}
		noSpaceWithoutFigures(t, fmt.Sprintf("chunk %d", i), rec)
	}
	if admitted != 2 {
		t.Fatalf("%d of bob's chunks hold a window, want the 2 that fit in half of 256 MiB", admitted)
	}
	share := createShare(t, h, "own")
	if rec := postBatch(t, h, share, testToken, batchOf(t, "own.bin", 128*mib), ""); rec.Code != 200 {
		t.Fatalf("another account's batch of half = %d %s", rec.Code, rec.Body)
	}
}

// A 1-byte reservation hides no stream: a chunk far past it holds a window
// every other admission sees.
func TestAOneByteReservationHidesNoStream(t *testing.T) {
	b := testBackend(t)
	diskOf(b, 10*gib) // 9 GiB usable
	h := New(b, "test", testDomain(t), nil)
	bob := seedUser(t, b.DB, "bob")
	carol := seedUser(t, b.DB, "carol")
	share := createShareAs(t, h, bob, `{"name":"tiny","reserveBytes":1}`)
	if _, dripping, rec := rangedDrip(t, h, bob, share, "big.bin", 4*gib); !dripping {
		t.Fatalf("the chunk answered %d before its body", rec.Code)
	}
	// The dripped byte spent the 1-byte draw, so the chunk holds one window.
	left := 9*gib - 64*mib
	noSpaceWithoutFigures(t, "a reservation past the stream's window",
		doReq(t, h, "POST", "/api/shares", carol, fmt.Sprintf(`{"name":"r","reserveBytes":%d}`, left+1)))
	if rec := doReq(t, h, "POST", "/api/shares", carol, fmt.Sprintf(`{"name":"r","reserveBytes":%d}`, left)); rec.Code != 201 {
		t.Fatalf("a reservation of what is left = %d %s", rec.Code, rec.Body)
	}
}

// An honest upload that reserves less than half draws its files from the
// reservation and goes through, its reservation counting against everyone
// else until it is drawn.
func TestAnHonestReservedUploadIsUnaffected(t *testing.T) {
	b := testBackend(t)
	b.FS.ReservePercent = 10
	b.FS.DiskSpace = func(string) (int64, int64, error) { return 1100, 10000, nil } // 100 usable
	h := New(b, "test", testDomain(t), nil)
	bob := seedUser(t, b.DB, "bob")
	carol := seedUser(t, b.DB, "carol")
	share := createShareAs(t, h, bob, `{"name":"files","reserveBytes":40}`)
	noSpaceWithoutFigures(t, "a reservation into bob's",
		doReq(t, h, "POST", "/api/shares", carol, `{"name":"r","reserveBytes":61}`))
	files := map[string]string{"a.txt": strings.Repeat("a", 10), "b.txt": strings.Repeat("b", 10), "c.txt": strings.Repeat("c", 10)}
	if rec := postBatch(t, h, share, bob, tarOf(t, files, nil), ""); rec.Code != 200 {
		t.Fatalf("batch = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+share+"/files/d.txt", bob, strings.Repeat("d", 10)); rec.Code != 201 {
		t.Fatalf("the last file = %d %s", rec.Code, rec.Body)
	}
	for name := range map[string]bool{"a.txt": true, "b.txt": true, "c.txt": true, "d.txt": true} {
		if f, err := b.DB.File(share, name); err != nil || f.Pending || f.Size != 10 {
			t.Fatalf("%s = %+v %v", name, f, err)
		}
	}
}

// A zip share reserves its whole archive and sends it as one range of the
// whole total: an archive larger than the account's half is admitted on its
// clamped reservation and lands.
func TestAZipLargerThanHalfLandsInOneRange(t *testing.T) {
	b := testBackend(t)
	b.FS.ReservePercent = 10
	b.FS.DiskSpace = func(string) (int64, int64, error) { return 1100, 10000, nil } // 100 usable, 50 per account
	h := New(b, "test", testDomain(t), nil)
	bob := seedUser(t, b.DB, "bob")
	share := createShareAs(t, h, bob, `{"name":"archive","reserveBytes":70}`)
	if rec := doReq(t, h, "PUT", "/api/shares/"+share+"/files/archive.zip", bob, strings.Repeat("z", 70)); rec.Code != 201 {
		t.Fatalf("the whole archive in one range = %d %s", rec.Code, rec.Body)
	}

	// The same shape at size: 7 GiB reserved on 9 GiB usable, one range of
	// 7 GiB, is admitted and holds no more than bob's half.
	big := testBackend(t)
	diskOf(big, 10*gib)
	hb := New(big, "test", testDomain(t), nil)
	bob = seedUser(t, big.DB, "bob")
	share = createShareAs(t, hb, bob, fmt.Sprintf(`{"name":"archive","reserveBytes":%d}`, 7*gib))
	if _, dripping, rec := rangedDrip(t, hb, bob, share, "archive.zip", 7*gib); !dripping {
		t.Fatalf("a 7 GiB archive on its clamped reservation = %d %s", rec.Code, rec.Body)
	}
	carol := seedUser(t, big.DB, "carol")
	if rec := doReq(t, hb, "POST", "/api/shares", carol, fmt.Sprintf(`{"name":"r","reserveBytes":%d}`, 9*gib/2)); rec.Code != 201 {
		t.Fatalf("another account's half beside it = %d %s", rec.Code, rec.Body)
	}
}
