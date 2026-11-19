package certpair

import (
	"context"
	"fmt"
	"strings"

	"github.com/caddyserver/certmagic"
)

// certsPrefix is the first segment of every certificate storage key.
// CertMagic keeps its own unexported copy of it; this one is pinned to it by
// TestTheAliasAgreesWithCertMagicsKeyLayout.
const certsPrefix = "certificates"

// FileOriginAlias answers a certificate asset addressed by a file origin with
// the app domain's own asset.
//
// Two facts about Let's Encrypt make it necessary. It byte-sorts the SAN set
// of every certificate it issues, discarding the order the request asked for,
// and the profiles this server orders under emit no Common Name. So the
// FIRST name on a cached certificate covering `<domain>` and `files.<domain>`
// is whichever of the two sorts first, which is the file origin for every
// domain that does not begin with a digit or with `a` to `e`. CertMagic
// addresses a managed certificate's stored resource, its ACME renewal
// information and its private key by that first name, while the resource is
// stored under the subject it manages, the app domain.
//
// Only an ASSET key is answered this way. A site FOLDER key is left alone,
// because the folder is a delete target: CertMagic's storage cleaner removes
// an emptied one and a revoke removes the whole folder, so answering the app
// domain's folder for a file origin's folder would delete a live certificate
// and its private key.
type FileOriginAlias struct {
	inner   certmagic.Storage
	managed *Subjects
}

func NewFileOriginAlias(inner certmagic.Storage, managed *Subjects) *FileOriginAlias {
	return &FileOriginAlias{inner: inner, managed: managed}
}

// rewrite answers the key an operation acts on. Everything that is not a
// certificate asset belonging to a managed domain's file origin, including
// every account key, lock name, OCSP staple and storage listing, is answered
// byte-identical.
func (a *FileOriginAlias) rewrite(key string) string {
	parts := strings.Split(key, "/")
	// Fewer than four segments is a folder: certificates, the issuer, the
	// site. Assets live one level below that.
	if len(parts) < 4 || parts[0] != certsPrefix {
		return key
	}
	app, ok := a.managed.AppDomain(parts[2])
	if !ok {
		return key
	}
	// Every asset is named after the site folder it sits in
	// (<domain>.crt, <domain>.key, <domain>.json and the compromised-key
	// copy). Anything else keeps its name.
	if !strings.HasPrefix(parts[3], parts[2]) {
		return key
	}
	parts[3] = app + parts[3][len(parts[2]):]
	parts[2] = app
	return strings.Join(parts, "/")
}

func (a *FileOriginAlias) Store(ctx context.Context, key string, value []byte) error {
	return a.inner.Store(ctx, a.rewrite(key), value)
}

func (a *FileOriginAlias) Load(ctx context.Context, key string) ([]byte, error) {
	return a.inner.Load(ctx, a.rewrite(key))
}

func (a *FileOriginAlias) Delete(ctx context.Context, key string) error {
	return a.inner.Delete(ctx, a.rewrite(key))
}

func (a *FileOriginAlias) Exists(ctx context.Context, key string) bool {
	return a.inner.Exists(ctx, a.rewrite(key))
}

func (a *FileOriginAlias) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	return a.inner.Stat(ctx, a.rewrite(key))
}

// List enumerates the real namespace, prefix and results alike. A listing is
// how CertMagic's storage cleaner walks every issuer, site and asset, and it
// hands each key it gets straight back to Load and Delete, so a listing that
// answered one folder's keys for another's would hand the cleaner keys it
// never enumerated.
func (a *FileOriginAlias) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	return a.inner.List(ctx, prefix, recursive)
}

func (a *FileOriginAlias) Lock(ctx context.Context, name string) error {
	return a.inner.Lock(ctx, a.rewrite(name))
}

func (a *FileOriginAlias) Unlock(ctx context.Context, name string) error {
	return a.inner.Unlock(ctx, a.rewrite(name))
}

// TryLock keeps the optional interface the file storage below this one
// implements. LockLeaseRenewer is deliberately NOT implemented: CertMagic
// treats its absence as "leases do not expire" and treats an error from it as
// a failed obtain, so offering it over a backend that cannot renew a lease
// would turn a no-op into a failed issuance.
func (a *FileOriginAlias) TryLock(ctx context.Context, name string) (bool, error) {
	locker, ok := a.inner.(certmagic.TryLocker)
	if !ok {
		return false, fmt.Errorf("certpair: %T does not implement TryLocker", a.inner)
	}
	return locker.TryLock(ctx, a.rewrite(name))
}

func (a *FileOriginAlias) String() string {
	return fmt.Sprintf("%v", a.inner)
}

var _ certmagic.Storage = (*FileOriginAlias)(nil)
var _ certmagic.TryLocker = (*FileOriginAlias)(nil)
