package certpair

import (
	"bytes"
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/caddyserver/certmagic"
)

// recordingStorage stands in for the file storage under the alias and keeps
// every key each method was handed, so a test can assert that a key reached
// the real namespace byte-identical.
type recordingStorage struct {
	contents map[string][]byte
	listing  map[string][]string
	seen     []string
	listed   []string
}

func newRecordingStorage() *recordingStorage {
	return &recordingStorage{contents: map[string][]byte{}, listing: map[string][]string{}}
}

func (r *recordingStorage) note(key string) { r.seen = append(r.seen, key) }

func (r *recordingStorage) Store(_ context.Context, key string, value []byte) error {
	r.note(key)
	r.contents[key] = value
	return nil
}

func (r *recordingStorage) Load(_ context.Context, key string) ([]byte, error) {
	r.note(key)
	value, ok := r.contents[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return value, nil
}

func (r *recordingStorage) Delete(_ context.Context, key string) error {
	r.note(key)
	delete(r.contents, key)
	return nil
}

func (r *recordingStorage) Exists(_ context.Context, key string) bool {
	r.note(key)
	_, ok := r.contents[key]
	return ok
}

func (r *recordingStorage) Stat(_ context.Context, key string) (certmagic.KeyInfo, error) {
	r.note(key)
	value, ok := r.contents[key]
	if !ok {
		return certmagic.KeyInfo{}, fs.ErrNotExist
	}
	return certmagic.KeyInfo{Key: key, Size: int64(len(value)), IsTerminal: true}, nil
}

func (r *recordingStorage) List(_ context.Context, prefix string, _ bool) ([]string, error) {
	r.listed = append(r.listed, prefix)
	return r.listing[prefix], nil
}

func (r *recordingStorage) Lock(_ context.Context, name string) error   { r.note(name); return nil }
func (r *recordingStorage) Unlock(_ context.Context, name string) error { r.note(name); return nil }

func (r *recordingStorage) TryLock(_ context.Context, name string) (bool, error) {
	r.note(name)
	return true, nil
}

// only returns the single key the storage below the alias was handed.
func (r *recordingStorage) only(t *testing.T) string {
	t.Helper()
	if len(r.seen) != 1 {
		t.Fatalf("the storage below the alias saw %v, want exactly one key", r.seen)
	}
	return r.seen[0]
}

const testIssuer = "acme-v02.api.letsencrypt.org-directory"

// The alias splits a certificate key into segments, so it has to agree with
// the layout CertMagic builds one from.
func TestTheAliasAgreesWithCertMagicsKeyLayout(t *testing.T) {
	asset := certmagic.StorageKeys.SiteCert(testIssuer, "zeta.example.com")
	parts := strings.Split(asset, "/")
	if len(parts) != 4 || parts[0] != certsPrefix {
		t.Fatalf("a certificate asset key is %q, want four segments beginning with %q", asset, certsPrefix)
	}
	if parts[2] != "zeta.example.com" || !strings.HasPrefix(parts[3], "zeta.example.com") {
		t.Fatalf("a certificate asset key is %q, want the domain as its folder and its file's stem", asset)
	}
	folder := certmagic.StorageKeys.CertsSitePrefix(testIssuer, "zeta.example.com")
	if got := len(strings.Split(folder, "/")); got != 3 {
		t.Fatalf("a site folder key is %q with %d segments, want three", folder, got)
	}
}

// Let's Encrypt byte-sorts the SAN set and DomainProfile emits no Common
// Name, so a paired certificate for a domain sorting after its file
// origin is cached with the FILE ORIGIN as its first name, and CertMagic
// renews and reloads a managed certificate by that first name. Both halves of
// resolving it back have to hold: the subject the order is placed for, and the
// stored resource the renewal reads and writes.
func TestTheRenewalSubjectOfAPairedCertificateResolvesToTheAppDomain(t *testing.T) {
	const app = "zeta.example.com"
	const first = "files.zeta.example.com" // what a paired leaf sorts first

	if app <= first {
		t.Fatalf("%q does not sort after %q, so this test is not exercising the case it names", app, first)
	}

	managed := NewSubjects(filesOrigin)
	managed.Add(app)

	if got := managed.Subject(context.Background(), first); got != app {
		t.Fatalf("the renewal subject for %q is %q, want %q", first, got, app)
	}

	inner := newRecordingStorage()
	want := []byte("the app domain's certificate")
	inner.contents[certmagic.StorageKeys.SiteCert(testIssuer, app)] = want
	inner.contents[certmagic.StorageKeys.SiteMeta(testIssuer, app)] = []byte("renewal info")
	alias := NewFileOriginAlias(inner, managed)
	ctx := context.Background()

	got, err := alias.Load(ctx, certmagic.StorageKeys.SiteCert(testIssuer, first))
	if err != nil {
		t.Fatalf("loading the certificate by the name it is renewed under: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("loaded %q, want the app domain's certificate", got)
	}
	if !alias.Exists(ctx, certmagic.StorageKeys.SiteCert(testIssuer, first)) {
		t.Fatal("the certificate does not exist under the name it is renewed under")
	}
	if _, err := alias.Stat(ctx, certmagic.StorageKeys.SiteMeta(testIssuer, first)); err != nil {
		t.Fatalf("stat of the renewal information: %v", err)
	}

	// ACME renewal information is read and written under the same first name,
	// which is what keeps the rate-limit exemption and the renewal window.
	if err := alias.Store(ctx, certmagic.StorageKeys.SiteMeta(testIssuer, first), []byte("newer renewal info")); err != nil {
		t.Fatalf("storing renewal information: %v", err)
	}
	if string(inner.contents[certmagic.StorageKeys.SiteMeta(testIssuer, app)]) != "newer renewal info" {
		t.Fatal("renewal information was written somewhere other than the app domain's metadata")
	}

	// The compromised-private-key copy is the private key's name with a
	// suffix, and it has to land beside the key it replaces.
	compromised := certmagic.StorageKeys.SitePrivateKey(testIssuer, first) + ".compromised"
	inner.seen = nil
	if err := alias.Store(ctx, compromised, []byte("pem")); err != nil {
		t.Fatalf("storing the compromised key copy: %v", err)
	}
	if want := certmagic.StorageKeys.SitePrivateKey(testIssuer, app) + ".compromised"; inner.only(t) != want {
		t.Fatalf("the compromised key copy went to %q, want %q", inner.seen[0], want)
	}
}

// Everything that is not a managed domain's certificate asset has to reach
// storage byte-identical, or the alias has quietly moved somebody else's data.
func TestEveryOtherKeyReachesStorageUnchanged(t *testing.T) {
	managed := NewSubjects(filesOrigin)
	managed.Add("zeta.example.com", "files.example.com", "example.com", "203.0.113.7")

	for _, tc := range []struct {
		label string
		key   string
	}{
		{"an ACME account key", "acme/" + testIssuer + "/users/default/default.json"},
		{"an ACME challenge token", "acme/" + testIssuer + "/challenge_tokens/files.zeta.example.com.json"},
		{"an OCSP staple named after the certificate's first name", "ocsp/files.zeta.example.com-9f86d081"},
		{"the storage read-write check key", "rw_test_4815162342"},
		{"a lock name", "issue_cert_files.zeta.example.com"},
		{"the certificates folder", certsPrefix},
		{"an issuer folder", certmagic.StorageKeys.CertsPrefix(testIssuer)},
		{"a site folder, even a file origin's", certmagic.StorageKeys.CertsSitePrefix(testIssuer, "files.zeta.example.com")},
		{"an app domain's own certificate", certmagic.StorageKeys.SiteCert(testIssuer, "zeta.example.com")},
		{"a file origin of a domain this server does not manage", certmagic.StorageKeys.SiteCert(testIssuer, "files.stranger.example.com")},
		{"a domain that merely begins with the file label", certmagic.StorageKeys.SiteCert(testIssuer, "filesystem.example.com")},
		{"a managed domain that begins with the file label", certmagic.StorageKeys.SiteCert(testIssuer, "files.example.com")},
		{"an asset not named after its folder", certsPrefix + "/" + testIssuer + "/files.zeta.example.com/README"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			ctx := context.Background()
			for _, op := range []struct {
				name string
				run  func(a *FileOriginAlias)
			}{
				{"Store", func(a *FileOriginAlias) { _ = a.Store(ctx, tc.key, []byte("v")) }},
				{"Load", func(a *FileOriginAlias) { _, _ = a.Load(ctx, tc.key) }},
				{"Delete", func(a *FileOriginAlias) { _ = a.Delete(ctx, tc.key) }},
				{"Exists", func(a *FileOriginAlias) { _ = a.Exists(ctx, tc.key) }},
				{"Stat", func(a *FileOriginAlias) { _, _ = a.Stat(ctx, tc.key) }},
				{"Lock", func(a *FileOriginAlias) { _ = a.Lock(ctx, tc.key) }},
				{"Unlock", func(a *FileOriginAlias) { _ = a.Unlock(ctx, tc.key) }},
				{"TryLock", func(a *FileOriginAlias) { _, _ = a.TryLock(ctx, tc.key) }},
			} {
				inner := newRecordingStorage()
				op.run(NewFileOriginAlias(inner, managed))
				if got := inner.only(t); got != tc.key {
					t.Fatalf("%s reached storage as %q, want %q", op.name, got, tc.key)
				}
			}
		})
	}
}

// A server whose own domain begins with the file label must address its own
// resources. Stripping the label unconditionally would send files.example.com
// to example.com, which is a different customer's name.
func TestAManagedDomainIsNeverTreatedAsAnothersFileOrigin(t *testing.T) {
	managed := NewSubjects(filesOrigin)
	managed.Add("example.com", "files.example.com")

	if app, ok := managed.AppDomain("files.example.com"); ok {
		t.Fatalf("files.example.com was aliased to %q while it is managed in its own right", app)
	}
	if got := managed.Subject(context.Background(), "files.example.com"); got != "files.example.com" {
		t.Fatalf("the renewal subject for files.example.com is %q", got)
	}
	// Its own file origin still resolves to it.
	if app, ok := managed.AppDomain("files.files.example.com"); !ok || app != "files.example.com" {
		t.Fatalf("AppDomain(files.files.example.com) = (%q, %v)", app, ok)
	}
}

// A domain this server has never managed is nobody's file origin here.
func TestAnUnmanagedNameIsNotAliased(t *testing.T) {
	managed := NewSubjects(filesOrigin)
	managed.Add("zeta.example.com")
	if app, ok := managed.AppDomain("files.stranger.example.com"); ok {
		t.Fatalf("a name this server does not manage was aliased to %q", app)
	}
	if got := managed.Subject(context.Background(), "files.stranger.example.com"); got != "files.stranger.example.com" {
		t.Fatalf("the renewal subject for an unmanaged name is %q", got)
	}
}

// A domain that enters management after boot has to be aliased from then on:
// a free name claimed at runtime and an operator-set domain both arrive that
// way.
func TestADomainAddedAfterBootIsAliased(t *testing.T) {
	managed := NewSubjects(filesOrigin)
	if _, ok := managed.AppDomain("files.later.example.com"); ok {
		t.Fatal("a domain nothing has managed yet was aliased")
	}
	managed.Add("later.example.com")
	if app, ok := managed.AppDomain("files.later.example.com"); !ok || app != "later.example.com" {
		t.Fatalf("AppDomain after the domain entered management = (%q, %v)", app, ok)
	}
}

// Listing enumerates the real namespace. The storage cleaner lists a site
// folder and then loads and deletes exactly the keys it got back, so those
// keys have to name the resource they were enumerated from.
func TestListingIsNeverAliased(t *testing.T) {
	managed := NewSubjects(filesOrigin)
	managed.Add("zeta.example.com")

	stale := certmagic.StorageKeys.CertsSitePrefix(testIssuer, "files.zeta.example.com")
	staleAsset := certmagic.StorageKeys.SiteCert(testIssuer, "files.zeta.example.com")
	inner := newRecordingStorage()
	inner.listing[stale] = []string{staleAsset}
	alias := NewFileOriginAlias(inner, managed)

	got, err := alias.List(context.Background(), stale, false)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(inner.listed) != 1 || inner.listed[0] != stale {
		t.Fatalf("listed %v, want %q unchanged", inner.listed, stale)
	}
	if len(got) != 1 || got[0] != staleAsset {
		t.Fatalf("listing answered %v, want %q unchanged", got, staleAsset)
	}
}
