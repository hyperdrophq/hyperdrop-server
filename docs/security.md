# Security model

What the server defends, how, and what it leaves to the operator. The HTTP behaviour referred to
here is specified in [`docs/api.md`](api.md); the deployment in
[`docs/configuration.md`](configuration.md). To report a vulnerability, see
[SECURITY.md](../SECURITY.md).

## What the server is trusted with

A HyperDrop server holds three kinds of things: **files** people shared or sent, **accounts**
(passwords, device tokens, second factors), and **the box** it runs on, since an administrator can
replace its binary. The design keeps each behind its own boundary:

- a link's **recipient** reaches one share's files, and only through the public routes;
- an **account** reaches its own shares, and an administrator additionally manages accounts and
  the server, never another account's shares;
- **root on the box** is reached only through a binary signed by a HyperDrop release key.

## Two origins

Uploaded bytes are served only from `files.<domain>`; the server's pages, the password form and
the API's browser-facing routes only from `<domain>`
([`docs/api.md` § Two origins](api.md#two-origins); the rule is `server/internal/api/origins.go`).
This is a browser trust boundary. `/view` serves an uploaded `.html` or `.svg` inline as a live
page, so on the page origin an uploaded file could read the access cookies of every share its
visitor had unlocked and draw a convincing copy of the password form under the real domain and
certificate. A second origin is the only fix; no response header is.

- A request for a payload route on the page origin (or on the bare IP address) is redirected to
  the files origin, and a page route on the files origin to the page origin. Every route is
  classified, and a test walks the router so a new route cannot go unclassified
  (`origincoverage_test.go`).
- The `/api/` surface answers on any host on purpose: it reads no cookie, only a bearer token, so a
  page on another origin has no more power over it than any HTTP client, and pinning it would
  break a client that reaches the server by IP before DNS resolves.
- The access cookie carries `Domain=<domain>` so it reaches the files origin, and is honoured there
  only for the request shapes a person produces (a navigation, an image or media load, "save link
  as"; never a frame, script, style or `fetch()`), so an uploaded page cannot use the visitor's
  cookies to read another protected share's bytes
  ([`docs/api.md` § The access gate](api.md#the-access-gate)).
- Without a domain (development mode) both origins are one and this boundary does not exist. A
  server therefore refuses to start without a domain unless `HYPERDROP_ALLOW_PRIVATE=1` says it is
  a development server.

**The sandbox.** A file a browser would render as a document (HTML, XHTML, SVG, XML, XSLT, any
`+xml` type, any type that does not parse) is served with
`Content-Security-Policy: sandbox allow-scripts allow-forms allow-popups allow-modals allow-downloads`.
It runs in an opaque origin: it cannot read anything else the files origin serves.
`allow-same-origin` and `allow-popups-to-escape-sandbox` (which would launder the same privilege
through a new window) are never added. `X-Content-Type-Options: nosniff` is on every response, so a
browser never second-guesses a declared type into HTML.

**The page policy.** Every page the server renders carries
`Content-Security-Policy: base-uri 'none'; object-src 'none'; form-action 'self' https://<domain> https://files.<domain>`.
The password form and the front page also refuse to be framed (`frame-ancestors 'none'`,
`X-Frame-Options: DENY`) against clickjacking.

**Protected websites** serve their assets under a short-lived grant in the address rather than the
cookie, because a sandboxed page's subresource requests carry neither cookie nor `Referer`. A
grant is signed over its own message (it is never accepted as a cookie, nor a cookie as a grant),
admits only non-document files, expires in 12 hours and dies with a password change
([`docs/api.md` § The access gate](api.md#the-access-gate)).

**Embedding.** An account with `noEmbed` makes its files refuse to load as another site's image,
media, frame or object (`Cross-Origin-Resource-Policy` plus a redirect for a request that announces
itself as a cross-site embed).

## Receive Inboxes are never served publicly

A Receive Inbox is the server's one anonymous write path, so what it holds was written by
strangers. Its content is never served on a public route: the public reads resolve their share
through one gate that refuses an inbox (`visibleShareVia`), and the few routes that need the unrefused
lookup check the inbox case themselves: the file routes (which let the owner's bearer download
through and nothing else), the unlock form and the inbox's own pages. `/view` answers `404` for an inbox's file even with the owner's bearer, so nothing a
stranger uploads renders as a page on any origin. A test walks the router and drives a real inbox
through every public route, proving each probe against an ordinary share that does serve the route
(`inboxcoverage_test.go`); a new public route must be added there.

Anonymous uploads are bounded: one path segment per name, with no control or bidirectional
formatting character; a `Content-Length` before the first byte; the inbox's own byte and file caps
(at most 10,000 files); 16 uploads in flight per inbox, 8 per address and 64 per server; the
owner's quota and the disk reserve, all decided again inside the commit transaction. A colliding
name is renamed, never overwritten. The page's grouping cookie carries no authority.

## Linked shares and the server's disk

A linked share serves a folder already on the server. Two boundaries apply, both checked by the
server: the roots the server process was configured with (`HYPERDROP_LINKED_ROOTS`,
`HYPERDROP_LINKED_SCAN`) gate every byte served, and the per-account allowlist an administrator
sets gates creating and browsing, and revokes existing sources when it narrows
([`docs/api.md` § Linked shares](api.md#linked-shares)).

Every linked byte is opened through an `os.Root` rooted at the root that holds the share's source,
so a symlink planted inside the folder cannot serve anything outside it: the kernel-level lookup
refuses to leave the root. The walk never enters a symlinked directory, lists a symlinked file only
when its target is a regular file inside the same source, and skips every name starting with `.`,
`@` or `#`. A linked share never deletes, moves or writes anything in the folder; deleting the share
leaves the folder untouched.

## Ids and paths

Every share id passes `shareid.ValidID` and every relative path `shareid.ValidRelPath` before any
query or filesystem path is composed from it: a relpath must be relative, clean, free of NUL,
backslash and `.`/`..` segments, and within length limits (Go's `filepath.IsLocal(".")` is true, so
`.` is refused explicitly). This matters because the router hands a `{id}` wildcard its
percent-decoded value, so a route that believes it holds one path segment can be reached with a
slash or a dot segment in it.

Uploads in flight are staged at `shares/<id>/parts/<sha256(relpath)>.part`, never under `files/`,
and only the server composes that name. A client that could name the staging path could splice its
bytes into another upload's part or land a part where a served file belongs. A staged part belongs
to the upload session that started it, so two writers to one path are last-writer-wins and never a
splice. Every relpath is normalized to Unicode NFC on arrival, so two spellings of one name are one
path everywhere a path is a key.

`/site/{id}/{path}` resolves a path against the share's own file list, never against the
filesystem, so nothing outside the share is addressable however it is spelled.

## Rows are the truth

The database is the record of what exists, and every write orders its steps so that a crash leaves
at worst a stray file, never a row pointing at nothing:

| Operation | Order | A crash between the steps leaves |
|---|---|---|
| Create a share | the row; the directory waits for the first upload | nothing |
| Commit an upload | rename the staged part into `files/`, then write the row, under the path's lock; a refused row puts the previous file back | a pending row over the final file, which a retry overwrites or the stalled-upload sweep removes with its row |
| Delete a share | the rows, then the directory | an orphan directory the boot pass removes |
| Move files | the rows, then the bytes; a failed rename moves the rows back | the share as it stood |
| Replace a file | the rows, then the bytes and tiles the rows no longer name | bytes no row names, invisible to every read |

## Passwords, tokens and secrets

- **Account passwords** are bcrypt hashes (cost 10). A chosen password is 8 to 72 bytes. At sign-in
  an unknown username costs a bcrypt compare like a known one, and both answer the same
  `bad-credentials`, so usernames cannot be probed by timing or by answer.
- **Device tokens** are 256 random bits (`hd_u_` and 64 hex), shown once and stored as their
  SHA-256. They do not expire; each is revoked individually, by a password change that signs other
  devices out, or by an administrator. A token younger than 24 hours cannot sign other devices out
  or mint a device link, so a freshly stolen token cannot lock the owner out of their other
  devices.
- **Invites** (`hd_i_`, 256 bits, 7 days, one use) and **device-link secrets** are stored as
  hashes. An invite does not sign in an account with a second factor.
- **Device links** sign a phone in from a device already signed in. Minting one asks no password:
  a device token older than 24 hours is enough. A mint that sends the password (and code) anyway is
  checked as a step-up and marks the link stepped up. A link lives 30 seconds unclaimed, renewed
  with a new secret for at most 3 minutes from the mint; the first phone to claim it has 5 minutes
  to finish, and a second claim burns it. Approval takes the number the phone shows, typed on the
  minting device, and a wrong number burns the link. On an account with a second factor, a link
  that was not stepped up also takes the current code at approval, so a stolen device token alone
  cannot add a phone there. The trade-off: on an account without a second factor, a device token
  older than 24 hours can add a phone without the password. The number on the phone still has to
  be typed on the minting device, which ties the approval to the phone that claimed but does not
  stop whoever holds the token, since they can claim and type it themselves. Changing the password
  signs every other device out (unless the change asks to keep them), phones added this way
  included. The address the phone claimed from is kept in memory only, for the minting device to
  show beside the phone's name during the claim's 5 minutes, and a restart forgets it. The database
  keeps an HMAC mark of the minting address (under the volume secret), and of the claim only
  whether its mark matched, which is how the minting device is told the phone is on the same
  network.
- **Recovery codes** are stored as SHA-256 and work once.
- **Second factors** are TOTP (SHA-1, 6 digits, 30 s) with one step of skew either side, and a code
  is never accepted twice: the newest accepted step is stored, and verification and its spend
  happen in the same transaction as what they authorize.
- **Step-up.** Changing a password, managing the second factor, granting an administrator
  identity, adopting a domain without proof, configuring DDNS and updating the server ask for the
  caller's password (and code) again, so a bearer token alone cannot take over an account or the
  box. Updating the server's binary additionally requires the caller to have a second factor.
  Minting a device link is not on this list: it takes the password only when the caller sends it,
  and otherwise its approval takes the code on an account with a second factor (above).
- **Administrators cannot lock themselves out**, and the server always keeps an active,
  never-expiring administrator.

### Sealed values

Two values are kept so their owner can read them back, sealed rather than in plaintext:

- a share's password (beside its bcrypt hash), so the owner sees it on every device;
- a second factor's TOTP secret, which the server needs to check codes.

Each is AES-256-GCM under a key derived with HKDF-SHA256 from the **volume secret**
(`<data>/secret`, 32 random bytes, mode 0600) and a label naming its one use. Associated data binds
each value to its row: a share password to its share id and its current bcrypt hash (so a copy
opens only while it is still the share's password), a TOTP secret to its username. The volume
secret is a file beside the database, never a row in it, so neither the database nor its backups
hold it. The same secret keys the access-cookie and site-grant HMACs, the visitor-count HMACs and
the device-link address HMACs, and the server's public `serverID` is a one-way HMAC of it.

## Guessing and rate limits

| Limit | Key | Rule |
|---|---|---|
| Sign-in passwords, invites, device-link claims and polls | client address (IPv6 by /64) | 10 wrong in an hour → blocked 12 hours (`429 locked-out`) |
| Second-factor codes at sign-in | address and account | same |
| Step-up passwords and codes, enrolment confirms | address and account (the address counter is shared with sign-in) | same |
| Share passwords (`/unlock`, `?pw=`) | client address, a separate counter | same |
| Password checks in progress | server-wide | 2 at once, 32 waiting, then `503`; share-password checks 2 at once, 1 per owner |
| Share creation (non-admin) | account | 30 at once, refilling at 300 an hour (`429 rate-limited`) |
| Anonymous inbox uploads | inbox, address, server | 16, 8 and 64 in flight |
| Live shares | account | 3 at once |
| Watch long-polls | account, server | 4 and 256 parked |
| Zip streams | owner, server | 1 and 2 at once |

A correct answer forgets only the guesses aimed at the same target. The counters are in memory: a
restart clears them, and existing cookies and tokens are unaffected by a block. Behind a TCP proxy,
the address is the one the proxy's PROXY header names, believed only from the peers listed in
`HYPERDROP_TRUSTED_PROXIES` and required from them; without that every visitor would share the
proxy's address and one person's guessing would lock everyone out.

Request bodies are judged by stalls rather than by time (a body that keeps arriving at any usable
rate never fails), and request headers must arrive within 10 seconds, so a client that trickles
cannot hold a connection open indefinitely.

## Updates

**Signatures.** Every official server binary has a release signature: a five-line text file

```
hyperdrop-server-signature 3
version 1.0.0
arch amd64
sha256 <64 lowercase hex of the uncompressed binary>
signature <base64 Ed25519 signature over the first four lines and a newline>
```

verified against the public keys compiled into the server (`server/internal/updatesig`). A
signature verifies only for the exact bytes, this host's architecture, and a version not older than
the one running, so an old signed binary cannot be replayed to downgrade a server.

**Staging is not installing.** The server process runs as an unprivileged user under a strict
systemd sandbox and cannot replace its own binary. One exception: on a host whose capability
bounding set lacks `CAP_NET_BIND_SERVICE` (some unprivileged containers), the service cannot be
granted that capability to bind ports 80 and 443, so the provisioner runs it as root instead, with
an empty capability set and the same sandbox, whose read-only file system (`ProtectSystem=strict`,
only the data directory writable) is then what keeps it from writing root's files, the installed
binary included. An update, whether an administrator uploads it
(`POST /api/server/update`, which needs the step-up with a second factor and checks the signature
before staging) or the self-updater downloads it (an official build with automatic updates on, which a new server
starts without unless its install chose them; checking the manifest's
length and SHA-256 and then the signature), is written to `<data>/update/staged.bin` with its
signature beside it, and the database is backed up first.

**The root updater decides.** A systemd path unit notices the staged file and runs the root-owned
`/usr/local/lib/hyperdrop/update.sh`, which:

1. enters `<data>/update` once, refusing it when it is not a real directory there (a link in its
   place is removed), and names the staged files relative to it from then on; copies at most one
   byte over each limit (256 MiB for the binary) of the staged binary and its signature into a
   root-owned location, out of the service account's reach, opening each once without following a
   link or waiting on a FIFO; removes the staged files; and refuses a copy that is empty or over
   its limit, so nothing the service account re-points after a check reaches root;
2. runs `hyperdrop-server verify-update` **with the binary already installed** on that copy: the
   keys compiled into the root-owned installed binary, not anything the service account or the API
   can write, decide what runs as root;
3. checks it is an ELF binary that runs on this host (`version`);
4. swaps it in, keeping the previous binary, restarts the service, and waits up to 90 seconds for
   `/api/health` to report the new version; otherwise it puts the previous binary back and restarts
   that.

A staged file is never executed before its signature has verified. A server whose installed
binary cannot verify the release keys cannot take an update over the API; it is updated over SSH.
A build of your own (one without `-X main.official=true`) never installs an update on its own,
though an administrator can still install an official release over it.

**The release check** reads an unsigned manifest over HTTPS and only follows redirects that stay on
the same scheme and host. The manifest decides only which version to fetch and what to remind
administrators of; the signature decides whether it is installed.

## What leaks when

**The database or a backup of it** (`hyperdrop.db`, `backups/*.db`) exposes: account names, roles
and settings; bcrypt hashes of account passwords and share passwords, open to offline guessing
(cost 10); the SHA-256 of every device token, invite and device-link secret (256-bit values, not
recoverable); SHA-256 hashes of recovery codes (about 50 bits each: reissue them after a leak);
share names, file names, paths, sizes, hashes and dates; push handles, device public keys and
tags; and the visitor and address HMACs (not reversible without the volume secret). It does
**not** expose the sealed share passwords or TOTP secrets, which need the volume secret.

**The volume secret** (`<data>/secret`) additionally lets its holder forge access cookies and site
grants for any share (passing every share password), open the sealed share passwords and TOTP
secrets, and link visitor rows back to cookies and addresses it already knows.

**The files** are plain files under `shares/`; the server does not encrypt them at rest. Whoever
reads the data directory reads every stored file, protected or not, and the sealed share passwords
add nothing to what they can already read.

**`<data>/ddns`** holds the free name's bearer token and a custom DDNS recipe with its DNS
provider credentials, in plaintext (mode 0600): whoever reads it can update that name's or that
zone's records.

**`<data>/certmagic`** holds the TLS private keys.

Treat the whole data directory, and every copy of it, as secret. The database alone is the least
sensitive part of it.

**What the server sends elsewhere.** Push notifications leave sealed to the device; the relay sees
a handle, a collapse id and ciphertext ([`docs/api.md` § Push notifications](api.md#push-notifications)).
The names service sees the free name, this server's id and public address. The release check sees
the server's address. The server logs every refused request by its route pattern, status and code
(never the path, a token or a password), and never logs a push handle or ciphertext.
