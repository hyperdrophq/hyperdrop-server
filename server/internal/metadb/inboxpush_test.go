package metadb

import (
	"strings"
	"testing"
	"time"
)

// inbox makes an inbox owned by alice and commits files into it, one per
// (path, session), each a second apart.
func inbox(t *testing.T, db *DB, name string, files ...[2]string) Share {
	t.Helper()
	d, err := db.CreateShare(CreateOptions{Name: name, Owner: "alice", Inbox: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if _, err := db.DeclareFile(d.ID, f[0], 1); err != nil {
			t.Fatal(err)
		}
		if _, err := db.CommitFile(CommitInput{ShareID: d.ID, Path: f[0], Size: 1, SHA256: "x", UploadSession: f[1]}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1100 * time.Millisecond) // keeps two commits apart whatever the clock's grain
	}
	return d
}

func TestTheInboxReadsCoverWhatTheAnnouncerNeeds(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	box := inbox(t, db, "Box", [2]string{"a.pdf", "s1"}, [2]string{"b.pdf", "s2"})
	sums, err := db.InboxSummaries("alice")
	if err != nil || len(sums) != 1 || sums[0].ID != box.ID || sums[0].Name != "Box" || sums[0].Newest == nil {
		t.Fatalf("summaries = %+v %v", sums, err)
	}
	if sums[0].SeenAt != nil || sums[0].NotifyOff || sums[0].Closed {
		t.Fatalf("a fresh inbox summary = %+v", sums[0])
	}
	all, err := db.InboxFilesAfter(box.ID, time.Time{})
	if err != nil || len(all) != 2 || all[0].Path != "a.pdf" || all[0].UploadSession != "s1" || all[1].UploadSession != "s2" {
		t.Fatalf("files = %+v %v", all, err)
	}
	if !sums[0].Newest.Equal(all[1].CommittedAt) {
		t.Fatalf("newest = %v, want the last commit %v", sums[0].Newest, all[1].CommittedAt)
	}
	later, _ := db.InboxFilesAfter(box.ID, all[0].CommittedAt)
	if len(later) != 1 || later[0].Path != "b.pdf" {
		t.Fatalf("after the first: %+v", later)
	}
	if n, _ := db.UnseenInboxFiles("alice"); n != 2 {
		t.Fatalf("unseen = %d, want 2", n)
	}
	seen := all[0].CommittedAt
	if _, err := db.UpdateShare(box.ID, UpdateOptions{SeenAt: &seen}); err != nil {
		t.Fatal(err)
	}
	if n, _ := db.UnseenInboxFiles("alice"); n != 1 {
		t.Fatalf("unseen after marking the first seen = %d", n)
	}
	sums, _ = db.InboxSummaries("alice")
	if sums[0].SeenAt == nil || !sums[0].SeenAt.Equal(seen) {
		t.Fatalf("seen at = %v, want %v", sums[0].SeenAt, seen)
	}
}

// The tab badge rule (InboxRules.tabBadge): a muted inbox counts nothing, a
// closed one still counts what arrived before it closed.
func TestAMutedInboxAddsNothingUnseen(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	box := inbox(t, db, "Box", [2]string{"a.pdf", "s1"})
	shut := inbox(t, db, "Shut", [2]string{"c.pdf", "s3"})
	must(t, errOf(db.UpdateShare(shut.ID, UpdateOptions{SetClosed: true, Closed: true})))
	if n, _ := db.UnseenInboxFiles("alice"); n != 2 {
		t.Fatalf("an open and a closed inbox counted %d, want 2", n)
	}
	must(t, errOf(db.UpdateShare(box.ID, UpdateOptions{SetNotify: true, Notify: false})))
	if n, _ := db.UnseenInboxFiles("alice"); n != 1 {
		t.Fatalf("a muted inbox still counted: %d, want 1", n)
	}
	sums, _ := db.InboxSummaries("alice")
	if len(sums) != 2 {
		t.Fatalf("summaries = %+v", sums)
	}
	for _, s := range sums {
		if s.ID == box.ID && (!s.NotifyOff || s.Closed) || s.ID == shut.ID && (s.NotifyOff || !s.Closed) {
			t.Fatalf("summary = %+v", s)
		}
	}
}

// Another account's inboxes and an ordinary share's files never count.
func TestTheInboxReadsStayWithTheOwnersInboxes(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	seedUser(t, db, "bob")
	inbox(t, db, "Box", [2]string{"a.pdf", "s1"})
	plain, err := db.CreateShare(CreateOptions{Name: "plain", Owner: "alice"})
	must(t, err)
	must(t, errOf(db.DeclareFile(plain.ID, "p.txt", 1)))
	must(t, errOf(db.CommitFile(CommitInput{ShareID: plain.ID, Path: "p.txt", Size: 1, SHA256: "x"})))
	if n, _ := db.UnseenInboxFiles("bob"); n != 0 {
		t.Fatalf("bob counted alice's inbox: %d", n)
	}
	if s, _ := db.InboxSummaries("bob"); len(s) != 0 {
		t.Fatalf("bob's summaries = %+v", s)
	}
	if n, _ := db.UnseenInboxFiles("alice"); n != 1 {
		t.Fatalf("alice's unseen = %d, want 1 (the plain share's file is not an inbox's)", n)
	}
	if s, _ := db.InboxSummaries("alice"); len(s) != 1 {
		t.Fatalf("alice's summaries = %+v", s)
	}
}

// A pending file is not an arrival.
func TestAPendingFileIsNotNew(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	box := inbox(t, db, "Box")
	must(t, errOf(db.DeclareFile(box.ID, "half.bin", 10)))
	if files, _ := db.InboxFilesAfter(box.ID, time.Time{}); len(files) != 0 {
		t.Fatalf("a pending file read as new: %+v", files)
	}
	if n, _ := db.UnseenInboxFiles("alice"); n != 0 {
		t.Fatalf("a pending file counted: %d", n)
	}
	if s, _ := db.InboxSummaries("alice"); len(s) != 1 || s[0].Newest != nil {
		t.Fatalf("summaries = %+v", s)
	}
}

func TestRevokedSourcesNameEachFolderTakenAway(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	seedUser(t, db, "bob")
	d := linkedShareFor(t, db, "alice", "photo/2024", "photo/2025", "docs")
	linkedShareFor(t, db, "bob", "photo/2024")
	two := 2
	roots := []string{"docs"}
	if _, err := db.UpdateUserAccess("alice", Settings{SourceRoots: &roots}, []SourceAccess{
		{ShareID: d.ID, Source: "photo/2025", Revoke: true},
		{ShareID: d.ID, Source: "photo/2024", Revoke: true, Files: &two},
	}, false); err != nil {
		t.Fatal(err)
	}
	got, err := db.RevokedSources("alice")
	if err != nil || len(got) != 2 {
		t.Fatalf("revoked = %+v %v", got, err)
	}
	if got[0].Source != "photo/2024" || got[1].Source != "photo/2025" {
		t.Fatalf("not in the order added: %+v", got)
	}
	if got[0].ShareID != d.ID || got[0].ShareName != "trip" || got[0].At.IsZero() {
		t.Fatalf("first = %+v", got[0])
	}
	if got[0].Files == nil || *got[0].Files != 2 || got[1].Files != nil {
		t.Fatalf("files = %v, %v", got[0].Files, got[1].Files)
	}
	if b, _ := db.RevokedSources("bob"); len(b) != 0 {
		t.Fatalf("bob's revoked = %+v", b)
	}
	if _, err := db.UpdateUserAccess("alice", Settings{}, []SourceAccess{
		{ShareID: d.ID, Source: "photo/2024"}, {ShareID: d.ID, Source: "photo/2025"},
	}, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.RevokedSources("alice"); len(got) != 0 {
		t.Fatalf("restored sources still read revoked: %+v", got)
	}
}

func TestAnInvalidIDReadsNothing(t *testing.T) {
	db := openTest(t)
	if _, err := db.InboxFilesAfter("../x", time.Time{}); err == nil {
		t.Fatal("an invalid id reached a query")
	}
}

// Every pusher read reaches its rows through an index: the owner's shares
// through a shares_owner_* index, an inbox's files through files_committed,
// a share's sources through share_sources' primary key. None scans a table.
func TestThePusherReadsUseIndexes(t *testing.T) {
	db := openTest(t)
	for name, c := range map[string]struct {
		sql  string
		args []any
		want []string
	}{
		"summaries":   {inboxSummariesSQL, []any{"alice"}, []string{"shares_owner_", "files_committed"}},
		"files after": {inboxFilesAfterSQL, []any{"x", int64(0)}, []string{"files_committed"}},
		"unseen":      {unseenInboxFilesSQL, []any{"alice"}, []string{"shares_owner_", "files_committed"}},
		"revoked":     {revokedSourcesSQL, []any{"alice"}, []string{"shares_owner_", "ss USING PRIMARY KEY"}},
	} {
		rows, err := db.r.Query("EXPLAIN QUERY PLAN "+c.sql, c.args...)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var plan []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, detail)
		}
		rows.Close()
		all := strings.Join(plan, "\n")
		t.Logf("%s:\n%s", name, all)
		for _, line := range plan {
			if strings.HasPrefix(line, "SCAN ") && !strings.Contains(line, "USING") {
				t.Errorf("%s scans a table: %q", name, line)
			}
		}
		for _, w := range c.want {
			if !strings.Contains(all, w) {
				t.Errorf("%s does not use %s:\n%s", name, w, all)
			}
		}
	}
}

// errOf drops a write's result, keeping its error.
func errOf[T any](_ T, err error) error { return err }
