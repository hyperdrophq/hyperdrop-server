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
