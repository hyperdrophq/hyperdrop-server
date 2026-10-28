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
- The `/api/` surface answers on any host on purpose: a call carries a bearer token, so a page on
  another origin has no more power over it than any HTTP client, and pinning it would break a
  client that reaches the server by IP before DNS resolves. The one cookie it reads is the web
  client's session, `__Host-hd_web`, on the app host alone, from a same-origin fetch of the web
  client, and only on the JSON routes `cookieroutes.go` lists (a test walking the router fails on
  an unlisted one); every other route refuses it. `/api` reads `__Host-hd_known` on
  `POST /api/web/session` alone, for a lane and nothing else.
- The access cookie names no `Domain`: it is host-only on each origin, so no other host under the
  domain receives it, which matters when the domain is an apex whose `www`, blog or CNAMEd hosts
  belong to someone else. A correct password on the page origin sets that origin's copy and passes
  the browser through `GET /access/{id}` on the files origin with a one-minute token signed for that
  share and password generation, which sets the files origin's own copy and forwards only to the
  share's own routes. On the files origin the cookie is honoured
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
owner's quota, checked before the first byte; and the disk. The quota and the inbox's caps are
decided again inside the commit transaction. The disk is admitted up front, where the whole file
must fit what is usable then, and held as a bounded rolling window: an upload promises other
uploads only its next 64 MiB at most, admitted again as its bytes land, and anonymous uploads
together hold at most half the usable space, so a stranger dripping a huge body holds one window
rather than the disk. A refusal names nothing of what the disk holds or what other uploads are
promised; only the configured system reserve is stated. A colliding name is renamed, never
overwritten. Bytes are stored by name, so on a data volume that matches names case-insensitively
(probed once at startup) a name the volume takes for a stored one collides too: `Report.pdf` beside
`report.pdf` becomes `Report 2.pdf`, and an owner's write names the stored spelling, so a share's
rows record one row per file the volume holds. The rule covers what is written while it applies,
not rows a server without it wrote. The lookup reads an indexed key every row carries, the
case-folded form of its path, so its cost does not depend on what else the share holds or on names
built to resemble a stored one; the server recomputes any missing or stale key each time it starts,
which covers rows an earlier release wrote after a rollback. A lookup that cannot answer (a row
with no key, or more than 32 stored spellings of one name the volume keeps apart) fails closed: an
anonymous upload is numbered or refused, and an owner's write is refused with 409, never written
over a stored file. The page's grouping cookie carries no authority.

A signed-in account is bounded the same way. Its reservations and its writes in progress, across
all its shares, hold at most half the usable space: a reservation past that is clamped, a window
past it refused. A write draws on its share's reservation when it is admitted, so a small
reservation hides no larger stream, and a reservation lives only while its share's uploads land
64 MiB of new bytes per 15 minutes, which re-sending the same range does not count. The half is
per account, so several accounts with no quota can together take what the anonymous pool
leaves: that is a trust the administrator grants by creating them, and a quota is how to limit
it.

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
`@` or `#`. An open reaches an entry the same way: down real directories only, each opened from its
parent's handle and checked to be the directory that was examined, so a folder swapped for a link
to a hidden folder after it was listed serves nothing. Every open of a share's served bytes (stored
and linked files, a video card's header read, gallery tiles, the poster) is non-blocking and reads
only an opened handle that is a regular file (for a stored or linked file, the one it examined), so
a FIFO swapped in cannot hold a request open. A linked share never deletes, moves or writes anything in the folder; deleting the share
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

- **Account passwords** are bcrypt hashes (cost 10). A chosen password is 8 to 72 bytes and is not one of the 10,000 most common ones. At sign-in
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
(`<data>/secret`, 32 random bytes, mode 0600; a secret found readable by other accounts is made
0600 at boot, or refuses the boot when the server cannot change it) and a label naming its one use. Associated data binds
each value to its row: a share password to its share id and its current bcrypt hash (so a copy
opens only while it is still the share's password), a TOTP secret to its username. The volume
secret is a file beside the database, never a row in it, so neither the database nor its backups
hold it. The same secret keys the access-cookie and site-grant HMACs, the visitor-count HMACs and
the device-link address HMACs, and the server's public `serverID` is a one-way HMAC of it.

## Guessing and rate limits

| Limit | Key | Rule |
|---|---|---|
| Sign-in passwords, invites, device-link claims and polls | client address (IPv6 by /64) | 10 wrong in an hour → blocked 12 hours (`429 locked-out`) |
| Sign-in and web sign-in passwords and codes, from any addresses | account lane (a kept browser's own lane for a web sign-in from a browser holding `__Host-hd_known`) | 10 failed sign-ins → one attempt per 30 seconds, `429 locked-out` with `Retry-After` of 30 at most; an hour without a failure resets it; never a block |
| Second-factor codes at sign-in | address and account | same as the address row |
| Step-up passwords and codes, enrolment confirms | address (shared with sign-in) and the calling token | same |
| Step-up passwords and codes, enrolment confirms, all of an account's tokens together | account | 20 wrong in an hour → every step-up of the account waits 1 hour |
| Share passwords (`/unlock`, `?pw=`, a Receive Inbox's page), first-party guesses only | client address (IPv6 by /64) and share, a separate counter | 10 wrong in an hour → blocked from that share 1 hour, twice the previous block while it repeats, up to 12 hours (an HTML `429` page) |
| Share passwords, from any addresses and any context | share lane | 10 failed → one guess per 30 seconds, an HTML `429` page; an hour without a failure resets it |
| Password checks in progress | server-wide | 2 at once, 32 waiting, then `503`; share-password checks 2 at once, 1 per owner |
| Share creation (non-admin) | account | 30 at once, refilling at 300 an hour (`429 rate-limited`) |
| Anonymous inbox uploads | inbox, address, server | 16, 8 and 64 in flight |
| Live shares | account | 3 at once |
| Watch long-polls | account, server | 4 and 256 parked |
| Zip streams | owner, server | 1 and 2 at once |

**A share-password guess counts on the address only from a first-party context.** That is a request
with no Fetch Metadata (the apps, curl, an older browser, and every browser on plain HTTP, which
sends Fetch Metadata only to HTTPS and localhost, so on a plain-HTTP server every browser guess
counts on the address), or a top-level document (`Sec-Fetch-Dest` absent or `document`) whose
`Sec-Fetch-Site` is `none` (typed, pasted, a bookmark; it stays `none` across the redirect between
the app origin and `files.<domain>`), `same-origin`, or `same-site` with an `Origin` naming one of
the server's own two hosts. A same-site request with no `Origin` or another one does not count:
another server's name under a shared parent is same-site too. A guess any other page makes the
visitor's browser send (an `<img>` with `?pw=`, a frame, a hosted `/site` page's fetch, a
cross-site navigation or form) is checked all the same, so a link or picture carrying its password
works, and counts on the share's lane alone: no website can lock its visitors, or everyone behind
their address, out of a share. A client that
writes `Sec-Fetch-Site: cross-site` itself is held by the share's lane alone, the same bound a
guesser spread over many addresses meets.

**The known-browser cookie.** A web sign-in with "This is my computer" sets `__Host-hd_known`
(`Path=/`, `HttpOnly`, `Secure`, `SameSite=Strict`, 180 days, no `Domain`), a random id signed with
an HMAC under a key derived from the volume secret and bound to the account as it exists now and
to its stored password hash. `/api`
reads it on `POST /api/web/session` alone, for a lane and nothing else: a valid one gives that
browser a sign-in lane of its own, so an owner's computer keeps its pace while strangers guess at
the account. A forged, expired or other-account cookie reads as absent, and the cookie is not a
credential. A sign-out and turning the web client off leave it valid; a password change or an
administrator's reset of the password makes every cookie of the account stop verifying, so whoever
once knew a password gains no lane under the next one, and the next kept sign-in sets a fresh
cookie. Each refusal's `Retry-After` is 30 seconds at most, but while someone keeps guessing, a new
browser or app signing in with a password alone may wait as long as that lasts; a kept browser,
phone sign-in, a linked device and an administrator's password reset are not affected. Lanes free
when an administrator resets the account's password or the account changes it. Lanes are in
memory and a restart clears them.

**Common passwords.** A chosen password is compared, after Unicode normalization and case folding,
against the 10,000 most common passwords of 8 to 72 bytes and refused when it is on the list
(`400`, no `code`). The list (`server/internal/commonpw`) is taken from the SecLists project's
`Passwords/Common-Credentials/10-million-password-list-top-100000.txt` (MIT licence, Daniel
Miessler and contributors; its data is Mark Burnett's public-domain 2015 release), pinned by
commit and SHA-256 and carried with its licence in `server/THIRD-PARTY-NOTICES.txt`. It is checked
only where a person chooses a password, never for a generated one, a sign-in or a share password,
so every existing password keeps working. The first administrator's password typed into an
installer is not checked.

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
systemd sandbox and cannot replace its own binary. It runs as that user on every host: where the
capability bounding set lacks `CAP_NET_BIND_SERVICE` (some unprivileged containers), the unit
cannot grant that capability, and the service binds ports 80 and 443 only where the host's
`ip_unprivileged_port_start` lets any account bind them, which is also the only place root could
without the capability. A box whose unit still runs the service as root moves to that user when
it is installed again (the install re-owns the data directory); an update keeps such a unit as it
is. The sandbox hides the host's control sockets outright
(`InaccessiblePaths` over `/run/dbus`, `/run/systemd/private`, the Docker, containerd and Podman
sockets), since a read-only file system does not stop a `connect()` to a socket. An update,
whether an administrator uploads it
(`POST /api/server/update`, which needs the step-up with a second factor and checks the signature
before staging) or the self-updater downloads it (an official build with automatic updates on, which a new server
starts without unless its install chose them; checking the manifest's
length and SHA-256 and then the signature, over a decompressing stream bounded at 128 MiB, so the
binary is never held in memory), is written to `<data>/update/staged.bin` with its
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
4. keeps the previous binary as a hard link to the file that was serving (and changes nothing when
   it cannot), swaps the new one in, restarts the service, and waits up to 90 seconds for
   `/api/health`, on the HTTP address `/etc/hyperdrop/server.env` sets, to report the new version;
   otherwise it puts the previous binary back and restarts that, provided the previous binary
   still runs;
5. once the new binary serves, refreshes the service unit, itself and its two units from the
   provisioner that binary embeds (`hyperdrop-server system-files`, run by root into a root-owned
   directory, never anything read from the staging directory), taking the box's values from the
   installed unit; every refreshed unit must load, the path unit that delivers the next update
   must stay enabled and active, and a changed service unit must serve, or every refreshed file
   goes back. Only a file shown to have failed is recorded, with the binary that rendered it, so
   staging that binary again leaves that file alone while every other file, and any later binary,
   tries again. The new binary stays when it serves under the files put back, and rolls back
   otherwise.

A staged file is never executed before its signature has verified. A server whose installed
binary cannot verify the release keys cannot take an update over the API; it is updated over SSH.
A build of your own (one without `-X main.official=true`) never installs an update on its own,
though an administrator can still install an official release over it.

**The release check** reads an unsigned manifest over HTTPS and only follows redirects that stay on
the same scheme and host. The manifest decides only which version to fetch and what to remind
administrators of; the signature decides whether it is installed.

**The web client** a server serves at `/app` is a signed bundle too, and it is installed the same
way: the server reads the web release manifest about once a day where automatic updates are on, and on a
server with them off once per server version and when an administrator asks (turning the web client
on, turning automatic updates on, or Update Server answering "already current"), and installs a bundle only when
its Ed25519 signature verifies against the keys in `core/webbundle` for that version, build,
contract and archive. A bundle is data the server serves, not a program it runs.

## The release keys

Two Ed25519 keys sign what a server installs, and each server trusts the public halves compiled
into the binary it runs:

| Key | Signs | Trusted from | Installed without an administrator |
|---|---|---|---|
| Server release key | server binaries | `server/internal/updatesig` | only on a server whose automatic updates are on |
| Web release key | web client bundles | `core/webbundle` | where automatic updates are on, and on a server with them off once per server version and when an administrator asks |

The private halves are kept on HyperDrop's release machine and its backup, never in this
repository, a CI system or the website's host, which receives only the signatures. A rotation adds
the new public key beside the old one in a release and keeps the old one for at least one more
release, so a server one release behind still verifies what the next release signs; only then is
the old key removed.

**If a release key is stolen.** A server keeps trusting every key compiled into the binary it
runs, and there is no revocation list yet. A stolen server key could sign a binary for any version
newer than the one a server runs; a stolen web key could sign a web client that runs on the app's
origin for everyone who opens `/app`. To reach a server, the thief also needs a way to deliver it:
control of the site a server reads its release manifests and files from (`HYPERDROP_SERVER_RELEASES`,
`HYPERDROP_WEB_RELEASES`, by default gethyperdrop.com), which would put the forgery on every server
that reads it within about a day (the server binary only where automatic updates are on, the web client only where automatic updates are on, and on a server with them off once per server version), or an administrator persuaded to upload it. Because the server
refuses a version older than its own, a server that installed a forged high version also refuses
every genuine release after it. HyperDrop would announce a compromise through a GitHub security
advisory and on gethyperdrop.com, and publish a release that no longer trusts the stolen key.

**What an administrator can do.**

- Keep automatic updates off and check a release before installing it: the server binaries are
  reproducible builds (`docs/reproducible-builds.md`), so a release that does not rebuild from its
  public tag is not one HyperDrop published from this repository, whatever its signature says.
  `platforms/linux/verify-release.sh <version> --installed /usr/local/bin/hyperdrop-server`
  checks the binary a server runs.
- Turn the web client off when it is not used (`PATCH /api/server/settings` `{"webApp":false}`), or
  stop the server fetching bundles with `HYPERDROP_WEB_RELEASES=` (`docs/configuration.md`).
- After an announced compromise, or for a binary that does not rebuild from a public tag,
  reinstall the server from a shell on the box: the one-line installer with
  `HYPERDROP_RESET_ADMIN=1` replaces the binary, keeps every share and sets a new administrator
  password. The binary installed that way is the one whose keys judge the next update.

## What leaks when

**The database or a backup of it** (`hyperdrop.db`, `backups/*.db`) exposes: account names, roles
and settings; bcrypt hashes of account passwords and share passwords, open to offline guessing
(cost 10); the SHA-256 of every device token, invite and device-link secret (256-bit values, not
recoverable); recovery codes keyed with the volume secret (HMAC-SHA256 of each code's SHA-256,
so the database alone gives none away; a backup taken before 1.3.1 still holds their plain SHA-256
until it rotates out);
share names, file names, paths, sizes, hashes and dates; push handles, device public keys and
tags; and the visitor and address HMACs (not reversible without the volume secret). It does
**not** expose the sealed share passwords or TOTP secrets, which need the volume secret.

**The volume secret** (`<data>/secret`) additionally lets its holder forge access cookies and site
grants for any share (passing every share password), open the sealed share passwords and TOTP
secrets, search the keyed recovery codes (about 50 bits each: reissue them after a leak of both),
and link visitor rows back to cookies and addresses it already knows.

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
