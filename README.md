# HyperDrop server

The share server behind [HyperDrop](https://gethyperdrop.com): a self-hosted service that turns
files and folders into links. It runs on any Linux box (a VPS, a home server, a container) or as a
Synology package, gets its own HTTPS certificate, and serves every share at a link that carries a
random id rather than a file name.

The HyperDrop apps (macOS, Windows, Linux, iPhone, Android) and the `hyperdrop` command line are
the clients. This repository holds the server they talk to and the Synology package that ships it.

## What it does

- **Shares**: upload files or folders and get a View link (opens in the browser when the browser
  can render it) and a Download link. Optional per-share password and expiry.
- **Receive Inboxes**: a public upload page strangers send files to; the content is never served
  publicly, only to the owner.
- **Linked shares**: share a folder that already lives on the server (a NAS shared folder) live,
  without copying it.
- **Live shares**: share a file from the sharer's own computer, relayed through the server on
  demand and never stored.
- **Galleries, text notes, static sites, link previews, accounts with quotas and two-factor
  sign-in, push notifications, signed self-updates.**

## Design in one paragraph

One Go binary, the standard library's HTTP server plus [CertMagic](https://github.com/caddyserver/certmagic)
for certificates, one SQLite database for every row (`server/internal/metadb`), and uploaded bytes
as plain files under `shares/<id>/files/` (`server/internal/sharefs`). Uploaded bytes are served
from a separate origin, `files.<domain>`, so an uploaded HTML page can never run on the origin that
holds a viewer's cookies (`server/internal/api/origins.go`). The HTTP API is described in
[`docs/api.md`](docs/api.md), the settings and the install layout in
[`docs/configuration.md`](docs/configuration.md), and the security model in
[`docs/security.md`](docs/security.md).

**You can check that a release is this source.** Every release tagged here rebuilds byte for byte
into the binaries gethyperdrop.com publishes, and `platforms/linux/verify-release.sh <version>`
proves it, for the downloads and for the binary installed on your own server:
[`docs/reproducible-builds.md`](docs/reproducible-builds.md).

## Layout

| Path | What it is |
|---|---|
| `server/` | The server (`package main`) and its internal packages |
| `core/` | The small, pure decision packages the server shares with every HyperDrop client (no I/O) |
| `platforms/synology/` | The DSM 7 and DSM 6.2 package sources and `build-spk.sh` |
| `core/provision/provision.sh` | The provisioner every Linux install runs: the service account, the systemd units, the root updater |
| `platforms/linux/` | The one-line Linux installer's template (`install.sh.in`) and its generator (`build-installer.sh`); the release build (`build-server.sh`) and the check of a release against this source (`verify-release.sh`) |
| `docs/` | The HTTP API reference, the configuration, the security model and reproducible builds |

## Build

Go 1.27.3 or newer, the `go` line of `server/go.mod`: older 1.27 releases build a server whose
standard library carries known vulnerabilities (net/http, crypto/tls, crypto/x509, html/template).

```sh
git clone https://github.com/hyperdrophq/hyperdrop-server.git
cd hyperdrop-server/server
go build -o hyperdrop-server .
go vet ./... && go test ./...
```

HyperDrop's releases are built with `platforms/linux/build-server.sh OUTDIR`, which pins the Go
toolchain and every build setting so the same source always builds the same bytes
([`docs/reproducible-builds.md`](docs/reproducible-builds.md)). It also passes
`-X main.official=true`, which lets a server install newer releases on its own (see "Release
check" below); a build without it never replaces itself.

## Run it locally

From the repository root:

```sh
docker build -f server/Dockerfile -t hyperdrop-server:dev .
docker run -e HYPERDROP_ADMIN_PASSWORD=change-me -e HYPERDROP_ALLOW_PRIVATE=1 \
  -e HYPERDROP_PUSH_RELAY= -e HYPERDROP_SERVER_RELEASES= \
  -p 127.0.0.1:8081:80 -v hyperdrop-data:/data hyperdrop-server:dev
```

The image runs as uid 10001. A volume an older (root) image created needs
`docker run --rm -v hyperdrop-data:/data alpine chown -R 10001:10001 /data` once.

`HYPERDROP_ALLOW_PRIVATE=1` with no `HYPERDROP_DOMAIN` is the development mode: plain HTTP on one
origin, no certificate. It does not exercise the separate files origin, so anything that depends on it (an uploaded `.html`
rendered by `/view`, the sandbox CSP) needs a real domain to test. The two empty variables turn
off push notifications and the daily release check (see below).

A production server needs a domain whose `A` record points at it (`HYPERDROP_DOMAIN`, plus a
`files.` record beside it) and its public IPv4 in `HYPERDROP_IP` (or `HYPERDROP_BEHIND_NAT=1`
behind a router that forwards its ports), and listens on 80 and 443. Every setting is an environment variable,
listed in [`docs/configuration.md`](docs/configuration.md#environment-variables).

## Network calls the server makes on its own

- **Certificates**: ACME (Let's Encrypt by default) for the domain and its `files.` origin, and a
  separate certificate for its public IPv4.
- **Release check**: 2 to 32 minutes after boot and then about once a day it reads the official release
  manifest from `gethyperdrop.com` and tells the server's admins when a newer release is out. An
  official build (one HyperDrop's release scripts link with `-X main.official=true`) on a Linux
  install with the root updater unit, when automatic updates are on, also installs that release once its Ed25519 signature verifies against the keys in
  `server/internal/updatesig`. A build of your own only reports the release and never replaces
  itself; an admin can still install the official release over it with Update Server in the
  HyperDrop apps. Turn the check off with `HYPERDROP_SERVER_RELEASES=` (empty).
  A new server starts with automatic updates off unless it is installed with
  `HYPERDROP_AUTO_UPDATE=1` ([`docs/configuration.md`](docs/configuration.md#environment-variables)).
- **Push relay**: when an account signs in a phone, the server sends end-to-end encrypted
  notifications through HyperDrop's relay (the relay sees only ciphertext). Turn it off with
  `HYPERDROP_PUSH_RELAY=` (empty).
- **Free names**: only when the owner asks for a free `<name>.hyperdrop.link` address, the server
  talks to HyperDrop's name registry to claim it and keep its address current.
- **Custom DDNS**: only when an admin sets up a DDNS recipe, the server sends that recipe's
  requests to the provider it names.
- **Address checks**: while a free name or a DDNS recipe is configured, the server learns its
  public IPv4 from HyperDrop's name registry (`GET /v1/ip`) about every five minutes and checks
  its own records by asking the public resolvers `1.1.1.1` and `8.8.8.8` (then the system
  resolver) and by fetching its own `/api/health` over HTTPS at its public address. A server with
  its own domain and neither makes these checks only when an admin runs one
  (`POST /api/connectivity/check`); its schedule sends nothing besides the reachability check
  below (behind NAT only).
- **Reachability check**: a server installed behind NAT (`HYPERDROP_BEHIND_NAT=1`) asks the
  same registry which public address it leaves from and whether its ports 443 and 80 answer from
  outside, at boot, on a domain change and every 30 minutes, so the apps can say what the router
  still needs. It also asks the router itself over
  UPnP for its external address (it never opens a port).

## Install on a server

The supported installs are the HyperDrop apps' Server Management, the one-line Linux installer
at <https://gethyperdrop.com/downloads/server/>, and the Synology package from the same page.
They install HyperDrop's official release builds: the one-line installer checks each download
against the SHA-256 it carries (below), and every later update over the API installs only once the
binary already installed verifies the new one's release signature.

The one-line installer (`curl -fsSL https://gethyperdrop.com/install.sh | sudo sh`) is generated
from files this repository carries: `platforms/linux/install.sh.in` with `core/provision/provision.sh` embedded
verbatim, the same provisioner Server Management uploads over SSH, and the SHA-256 of each
architecture's download taken from the newest entry of the server manifest. The installer
downloads that release and refuses a binary whose checksum does not match; it does not check the
release signature, which the installed binary checks on every later update. To generate one from
this tree:

```sh
curl -fsSLO https://gethyperdrop.com/downloads/server/releases.json
platforms/linux/build-installer.sh --manifest releases.json --out install.sh
```

## Build the Synology package

```sh
platforms/synology/build-spk.sh <output directory>
```

builds one `.spk` per DSM generation and CPU family listed in `platforms/synology/arches.tsv`.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

The server and the Synology package are licensed under the GNU Affero General Public License,
version 3 only (`AGPL-3.0-only`, [LICENSE](LICENSE)). If you run a modified server for other people, the AGPL asks you to
offer them its source. The third-party software the server links is listed with its licences in
[`server/THIRD-PARTY-NOTICES.txt`](server/THIRD-PARTY-NOTICES.txt). The HyperDrop name and logo
are not covered by the code licence; see [TRADEMARKS.md](TRADEMARKS.md).
