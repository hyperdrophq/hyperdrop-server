# Security policy

## Reporting a vulnerability

Please report a vulnerability privately, never in a public issue, in either of two ways:

- through GitHub's private vulnerability reporting: the **Security** tab of
  [github.com/hyperdrophq/hyperdrop-server](https://github.com/hyperdrophq/hyperdrop-server), then
  **Report a vulnerability**
  ([direct link](https://github.com/hyperdrophq/hyperdrop-server/security/advisories/new));
- by email to **security@gethyperdrop.com**.

Include what an attacker needs (an account? a share link? nothing?), the request that shows it,
and what they gain. Reporters are credited in the release notes unless they prefer not to be
named.

## Supported versions

Only the newest release receives fixes. Official builds update themselves (see README, "Release
check"), so a fix reaches a Linux server that installs its own updates within about a day of its
release; a Synology package is updated through Package Center, and a build of your own by
whoever built it.

## How releases are trusted

Every official server binary carries an Ed25519 signature over its version, architecture and
SHA-256. A server installs an update only when the binary already installed verifies that
signature against the public keys in `server/internal/updatesig`, and it refuses a version older
than its own. The root-owned installer copies the staged file out of the service account's reach
before that check runs, so staging a file never equals running it.

The web client a server serves at `/app` is a signed bundle as well, verified against the keys in
`core/webbundle` before it is installed. What each release key controls, how a key is rotated, and
what to do if one is stolen: [`docs/security.md` § The release keys](docs/security.md#the-release-keys).

The keys behind HyperDrop's other downloads are listed here as well, so that they can be checked
against a source other than gethyperdrop.com:

- the package signing key for the apt and dnf repository and every `.rpm`:
  `9D09 3499 BE6A DB30 C38F 3DAE 80AC 6826 B880 0F72`;
- the Android app's signing certificate, SHA-256:
  `5D:52:ED:33:33:73:13:67:09:37:AE:47:20:F7:EB:DD:17:B5:F8:BB:EC:44:2B:98:6B:E7:BE:BF:FA:B4:9C:C7`;
- the macOS apps' Developer ID team: `MG4RZ3LTJ2`.

## What the server defends

The full model, including what a leaked database or backup does and does not expose, is in
[`docs/security.md`](docs/security.md). In short:

- Uploaded bytes are served from a separate origin (`files.<domain>`), and uploaded documents
  render under a `Content-Security-Policy: sandbox` that allows scripts but never
  `allow-same-origin`, so an uploaded page cannot reach a viewer's cookies on the app's origin
  (`server/internal/api/origins.go`).
- A Receive Inbox's content is never served on a public route; only its owner reads it.
- A linked share serves only the folders the server was configured with and an admin granted,
  and every byte opens through `os.Root`, so a symlink cannot reach outside them.
- Every id and relative path is validated before it reaches a query or a path.
- Account tokens are 256-bit random values stored as SHA-256; passwords are bcrypt. Wrong
  sign-in and share passwords are rate limited per address; wrong second-factor codes, and the
  password re-entered to confirm a sensitive change, per address and per account.

## Deliberate trade-offs

Reviews of this repository, by people and by automated agents, regularly report the points below.
Each one is a choice the security model states, not an oversight, so it is not a vulnerability on
its own. A report that shows one of them doing more than is described here is a vulnerability, and
welcome.

| Reported as | What is so | Stated in |
|---|---|---|
| Device tokens never expire | Each is revoked on its own, by an administrator, or by a password change that signs the other devices out. Every device is listed with when it was last used. A token under 24 hours old cannot sign other devices out, and every new sign-in alerts the account's other devices. | [Passwords, tokens and secrets](docs/security.md#passwords-tokens-and-secrets) |
| Files are not encrypted at rest | The data directory is the boundary: whoever reads it reads every stored file. Encrypt the disk and every backup. | [What leaks when](docs/security.md#what-leaks-when) |
| The server can read share passwords back | A share's password is sealed under the volume secret so its owner sees it on every device, and it is checked against its bcrypt hash. The database alone does not open it, and whoever holds the volume secret can already read the files the password protects. | [Sealed values](docs/security.md#sealed-values) |
| There is no revocation for a stolen release key, and a forged high version blocks later updates | Both are stated, with what HyperDrop does and what an administrator can do. Reproducible builds give a check that does not depend on the key. | [The release keys](docs/security.md#the-release-keys) |
| The one-line installer checks a SHA-256, not the release signature | The installer and the binaries it fetches come from the same site, so a key pinned in that installer would add no independent check. The installer is the trust root of a new box; every later update must pass the installed binary's signature check. | [Updates](docs/security.md#updates) |
| The load guard's request and connection limits only rise | Free memory falls under the server's own load, so each limit is the highest the server has read. When other programs take the memory, the separate low-memory line refuses new requests once 64 are running, and on a Linux install the systemd unit's `MemoryMax` ends the service before the machine runs out. | [The load guard](docs/api.md#the-load-guard), [configuration](docs/configuration.md) |
| A publicly posted live share can be kept busy by whoever controls enough addresses | A live share's transfer limits protect the sharer's computer and connection, and raise the cost of occupying a share: one address (an IPv4 address, an IPv6 /48) holds a tenth of the share's places, so a share takes at least ten networks to hold; a freed place goes to the waiting address that holds the fewest; and while anyone waits, a transfer that moves almost no data is ended, so every place held has to keep pulling data through the sharer's uplink. They do not make a public link impossible to occupy. A share password is the control for that: a visitor without it never reaches a transfer. | [Guessing and rate limits](docs/security.md#guessing-and-rate-limits), [What a visitor sees](docs/api.md#what-a-visitor-sees) |
| The route coverage tests read source code instead of the router | `http.ServeMux` cannot list what it holds, so the tests parse `server/internal/api` and fail on any route they cannot read: a `Handle` or `HandleFunc` call outside `api.go`, or a pattern that is not a string literal (`routesource_test.go`). The origin split, cookie routes, Receive Inbox containment and the second-factor allow-list all use that one list. | [Two origins](docs/security.md#two-origins) |
| A local run serves both origins from one host | That is the development mode, `HYPERDROP_ALLOW_PRIVATE=1` with no domain. A production server always splits them. | [Run it locally](README.md#run-it-locally) |
| The container could be hardened further (`read_only`, `cap_drop`, `no-new-privileges`) | The image runs as uid 10001 with only `CAP_NET_BIND_SERVICE`; the rest belongs to how a container is run, and a Linux install's systemd unit applies it: `NoNewPrivileges`, `ProtectSystem=strict` with only the data directory writable, a system-call filter and more. | [configuration](docs/configuration.md) |
| One SQLite file and one machine | That is the design: one server per box, with every row in one file and the bytes as plain files beside it. | [README](README.md#design-in-one-paragraph) |

This repository's own checks run `go vet`, the whole test suite under the race detector,
`staticcheck` and `govulncheck`, and a commit is published here only after they pass. A `govulncheck` advisory listed
only "in packages you import" or "in modules you require" is one the analysis found no call to:
a later dependency update picks it up, and it is not handled as a vulnerability.
