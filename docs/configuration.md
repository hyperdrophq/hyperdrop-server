# Configuring and running the server

`hyperdrop-server` is one static binary. Everything it needs to know about where it runs comes
from environment variables; everything it learns at runtime (accounts, shares, its domain, its
certificates) lives in its data directory. This page lists every variable the server reads, the
layout of the data directory, the ports, the operator subcommands, and what the Linux installer
and the Synology package set up.

The HTTP API is described in [`docs/api.md`](api.md) and the security model in
[`docs/security.md`](security.md).

## The three ways to boot

The server decides its mode from the environment when it starts, and refuses to start on a
combination that cannot work, with a message naming the variable to fix:

- **A public IPv4.** `HYPERDROP_DOMAIN` (or `HYPERDROP_DDNS_NAME`) plus `HYPERDROP_IP`, the box's
  own public IPv4. The server orders one Let's Encrypt certificate covering `<domain>` and
  `files.<domain>` and a separate one for the IP address, and serves HTTPS on
  `HYPERDROP_HTTPS_ADDR`.
- **Behind NAT.** `HYPERDROP_DOMAIN` (or `HYPERDROP_DDNS_NAME`) plus `HYPERDROP_BEHIND_NAT=1` and no
  `HYPERDROP_IP`: a router forwards public port 443 (and 80) to this box. There is no address to
  certify; ACME decides whether the box is reachable.
- **Development.** `HYPERDROP_ALLOW_PRIVATE=1` and no domain: plain HTTP on `HYPERDROP_HTTP_ADDR`,
  both origins collapsed onto one, no certificate. This mode does not exercise the separate files
  origin (see [`docs/security.md`](security.md#two-origins)), so it is for local development only.

A domain is required in every other case. Uploaded bytes are served from `files.<domain>`, a
second origin, and an IP address or a second port cannot be split that way (cookies ignore
ports). Both `<domain>` and `files.<domain>` need an `A` record pointing at the server.

## Environment variables

Every variable the server reads. Unset and empty mean the same thing unless the row says
otherwise.

| Variable | Meaning | Default |
|---|---|---|
| `HYPERDROP_DATA` | The data directory (below). | `/data` |
| `HYPERDROP_DOMAIN` | The domain the server serves. Share pages, the API and the password form answer on it; uploaded bytes answer on `files.<domain>`. Lowercase, LDH labels, at least two labels. Required unless `HYPERDROP_DDNS_NAME` or `HYPERDROP_ALLOW_PRIVATE=1` is set. Read at boot as a seed: a domain changed at runtime with `PUT /api/domain` is stored in the data directory and wins over this value on later boots. | unset |
| `HYPERDROP_DDNS_NAME` | A free `<name>.hyperdrop.link` address the server claims from the names service at boot, in place of `HYPERDROP_DOMAIN` (setting both refuses to start). 5 to 32 characters of lowercase letters, digits and hyphens. A claim that fails does not stop the boot: the server serves over its IP and `GET /api/ddns` explains why. | unset |
| `HYPERDROP_IP` | This server's public IPv4. Required with a domain unless `HYPERDROP_BEHIND_NAT=1`; a value that is not a public IPv4 refuses to start (IPv6 is not accepted). It is the reference point for "does the domain point here" and gets a certificate of its own, so the server answers HTTPS on its address before DNS has moved. It is never the server's identity: links name the domain. | unset |
| `HYPERDROP_BEHIND_NAT` | `1`: a domain without `HYPERDROP_IP`, for a box behind a router that forwards 443 (and optionally 80). Also starts the reachability probe reported by `GET /api/domain` (`nat`, `ports`). A set `HYPERDROP_IP` that is not public still refuses to start. | unset |
| `HYPERDROP_ALLOW_PRIVATE` | `1`: development mode (above) when no domain is set. It also allows plain `http` for `HYPERDROP_PUSH_RELAY` and for `HYPERDROP_NAMES_URL` to any host, and is required by `HYPERDROP_WEB_DEV_DIR` and `HYPERDROP_WEB_DEV_KEYS`. | unset |
| `HYPERDROP_HTTP_ADDR` | The plain-HTTP listen address: the ACME HTTP-01 challenge, `/api/health`, `/.well-known/hyperdrop-names` and a redirect to HTTPS in HTTPS mode; the whole server in development mode. | `:80` |
| `HYPERDROP_HTTPS_ADDR` | The HTTPS listen address. Change both addresses only when the host already owns 80 and 443 (a Synology's own web server, say); the public ports at the router stay 80 and 443. | `:443` |
| `HYPERDROP_ADMIN_USER` | The first administrator's username, used on the first boot of a volume that has no administrator (3 to 32 of `a-z 0-9 . _ -`; anything else refuses to start). Ignored once any administrator exists. For the `resetadmin` subcommand it names the administrator to reset (or a new one to create beside the existing ones); empty there means the sole administrator. | `admin` |
| `HYPERDROP_ADMIN_PASSWORD` | The first administrator's password, read on the first boot of a volume with no administrator, for a server started by hand or in a container. A volume with no administrator and no password refuses to start. Removed from the process environment after the first-boot check, whether or not it was used. The `resetadmin` subcommand does not read it. | unset |
| `HYPERDROP_ADMIN_PASSWORD_FILE` | A file holding that password, read in its place when the file exists. The installer and the Synology package use it so the password never enters a unit file or the server's environment. The server removes the file once the volume has an administrator, whether it created one from the file or found one already there (the log then says the seed was ignored). Only a volume with no administrator fails to boot on a seed it cannot read. The `resetadmin` subcommand reads the password it sets from this file too, byte for byte, and removes it. | unset |
| `HYPERDROP_AUTO_UPDATE` | Whether a NEW volume installs each release on its own: `1`, `on` or `true` turns automatic updates on; unset, empty, `0`, `off` or `false` leaves them off. Read only on the boot that creates the volume's first administrator, which records the choice before the administrator exists; a volume that already has an administrator keeps its switch, so a server installed before the choice existed keeps updating itself. Any other value refuses to start. Afterwards an administrator turns the switch in the apps (`PATCH /api/server/settings`), and the box's owner with the `auto-update` subcommand. | unset (off) |
| `HYPERDROP_DISK_RESERVE` | Unset, the server keeps a flat 1 GiB of the disk free for the system (at most a quarter of the disk). Set, a percent of the disk instead, 0 to 90 (anything else refuses to start): the reserve is then the larger of this percentage and 1 GiB on a disk over 4 GiB, and `0` turns it off. An upload that would dip into the reserve is refused `507 no-space`. | unset (1 GiB) |
| `HYPERDROP_ABANDONED_UPLOAD_TTL` | How long after its last byte an interrupted upload is abandoned: its staged part and its pending file entry are removed, and a share left with nothing goes with them. A Go duration (`45m`, `12h`); an unparseable or non-positive value is ignored, so a typo cannot turn the sweep off. | `3h` |
| `HYPERDROP_LIVE_SHARE_GRACE` | How long a live share outlives its sharer's connection before its links stop answering. A Go duration; an unparseable or non-positive value is ignored. | `5m` |
| `HYPERDROP_LINKED_ROOTS` | Colon-separated directories a linked share may serve from, each named by its own base name. Two roots with one base name refuse to start. See [`docs/api.md` § Linked shares](api.md#linked-shares). | unset |
| `HYPERDROP_LINKED_SCAN` | Colon-separated parent directories whose readable top-level subdirectories each become a root named after itself. A name starting with `.`, `@` or `#` is skipped, and a name `HYPERDROP_LINKED_ROOTS` already uses wins. Re-scanned at most once a minute, so a folder created later becomes shareable without a restart. | unset |
| `HYPERDROP_TRUSTED_PROXIES` | Comma-separated addresses or CIDR prefixes of TCP pass-through proxies whose PROXY protocol header (v1 or v2) the HTTPS listener believes, so the per-address lockouts and the visitor counts see each visitor's real address. A listed peer must send the header on every connection; an unlisted peer that sends one is refused. Nothing is trusted implicitly, loopback included (list an on-box proxy as `127.0.0.1`). Port 80 never speaks PROXY. A malformed entry or a catch-all (`0.0.0.0/0`, `::/0`) refuses to start. Unset or empty lists no proxy, so every header is refused, and a refused header is reported as the health reason `proxy-header`. | unset (every PROXY header refused) |
| `HYPERDROP_CHANNEL` | The install manager that owns the binary, reported as `channel` by `GET /api/health`. `synology` means Package Center: the update route refuses and clients send the admin there. It also sends the log to the log file alone instead of the file and stderr. | unset |
| `HYPERDROP_PLATFORM` | The package family, reported as `platform` by `GET /api/health` when it is `dsm7` or `dsm6` (the Synology package sets it from the DSM major version); other values are not reported. | unset |
| `HYPERDROP_STATUS_FILE` | A small JSON file the server keeps current (version, start time, the last startup refusal, stored files missing from disk, whether the outside port check reached it, an address change still waiting), written only when its content changes. The Synology package sets it so its settings page can read it while the server is stopped. | unset |
| `HYPERDROP_ADDRESS_REQUEST` | A one-line file asking for an address change, `free <name>` or `domain <fqdn>`, which the Synology package writes from its wizard while the server may be stopped. The server reads it after boot and then every 10 minutes, and switches only once the new address is proven: an own domain when it and `files.<domain>` resolve to this server's public IPv4, a free name when it is approved and published. Meanwhile the old address serves and the wait is the health reason `address-pending`. A request it will not carry out (malformed, not a regular file, or a different free name) is deleted and reported in the status file. An address change made in the app replaces a waiting request. | unset |
| `HYPERDROP_CONF` | The Synology package's settings file, whose `HYPERDROP_DOMAIN` and `HYPERDROP_DDNS_NAME` lines the server keeps naming its current address (at boot and on every address change, whichever path made it): a free name is `HYPERDROP_DDNS_NAME=<name>` with `HYPERDROP_DOMAIN` empty, an own domain the reverse. Every other line is left as it is; a file that is not a regular file of its own is left alone, with a log line. | unset |
| `HYPERDROP_UPDATE_DIR` | The directory `POST /api/server/update` and the self-updater stage a new binary in, which the root-owned updater unit watches (below). Unset turns the update route off and `GET /api/health` reports no `updateOverAPI`. | unset |
| `HYPERDROP_SERVER_RELEASES` | The directory whose `releases.json` (the server release manifest) the server reads 2 to 32 minutes after boot and then about once a day, to remind its admins of a newer release and, on an official build, to install it. An absolute `https` URL without credentials, query or fragment (plain `http` only to a loopback host). Set and empty turns the check off; a malformed value also turns it off, with a log line. | `https://gethyperdrop.com/downloads/server/` |
| `HYPERDROP_WEB_RELEASES` | The directory whose `releases.json` (the web release manifest) the server reads 30 seconds after boot, then about once a day and whenever an administrator turns the web client on, to install the web client's bundle this server serves (see [`docs/api.md` § The web client](api.md#the-web-client)). The same rules as `HYPERDROP_SERVER_RELEASES`. Unset, it is the `web/` directory beside `HYPERDROP_SERVER_RELEASES` when that is set (so an empty `HYPERDROP_SERVER_RELEASES` turns this fetch off too). Set and empty turns the fetch off; a malformed value also turns it off, with a log line. | `https://gethyperdrop.com/downloads/web/` |
| `HYPERDROP_WEB_DEV_DIR` | An absolute path to a directory `/app` serves unsigned in place of any installed bundle, for developing the web client. Honoured only with `HYPERDROP_ALLOW_PRIVATE=1`: set without it, a relative path, or a path that is not a directory refuses to start. | unset |
| `HYPERDROP_WEB_DEV_KEYS` | Comma-separated base64 Ed25519 public keys trusted beside the web release keys for a bundle's signature, for testing a development build of the web client. Honoured only with `HYPERDROP_ALLOW_PRIVATE=1`: set without it, or a key that is not a 32-byte Ed25519 public key, refuses to start. | unset |
| `HYPERDROP_PUSH_RELAY` | The relay push notifications are sent through (see [`docs/api.md` § Push notifications](api.md#push-notifications)): an `https` origin with no path, query, fragment or credentials (`http` only with `HYPERDROP_ALLOW_PRIVATE=1`). Set and empty turns push off; a malformed value also turns it off, with a log line. | `https://api.gethyperdrop.com` |
| `HYPERDROP_NAMES_URL` | The names service a free name is claimed and kept current through, and which dials the server's ports back from outside: an absolute `https` URL without credentials, query or fragment (`http` only to a loopback host, or anywhere with `HYPERDROP_ALLOW_PRIVATE=1`). The name's bearer token travels on every request, so a malformed value refuses to start. | `https://api.gethyperdrop.com` |
| `HYPERDROP_DDNS_ALLOW_PRIVATE` | `1` lets a custom DDNS recipe that asks for it (`allowPrivate`) send requests to private and reserved addresses. Without it such a recipe is refused when saved, and a stored one only reaches public addresses. | unset |
| `HYPERDROP_ACME_EMAIL` | The ACME account email. | unset |
| `HYPERDROP_ACME_CA` | An ACME directory URL in place of Let's Encrypt (its staging environment, or a private CA in tests). | Let's Encrypt |
| `HYPERDROP_ACME_CA_CERT` | PEM of a private ACME CA's TLS certificate, trusted for the ACME connection (tests against a local CA). Invalid PEM refuses to start. | unset |

## Ports

| Port | Serves |
|---|---|
| 443 (`HYPERDROP_HTTPS_ADDR`) | HTTPS for `<domain>`, `files.<domain>` and the public IPv4: every page, the API and every byte. TLS 1.2 or newer, HTTP/2 offered. |
| 80 (`HYPERDROP_HTTP_ADDR`) | The ACME HTTP-01 challenge, `GET /api/health`, `GET /.well-known/hyperdrop-names`, and a `308` to HTTPS for everything else. A request already addressed to the domain or its files origin keeps that name; any other host goes to the domain. |

Both must be reachable from the internet for certificates to issue (HTTP-01 on 80). The server
sets no whole-request timeout, so a long upload or download runs as long as it needs; request
headers must arrive within 10 seconds, and a request body is cut off when it stalls (see
[`docs/api.md` § Conventions](api.md#conventions)).

## The data directory

Everything the server keeps lives under `HYPERDROP_DATA`. Back up the whole directory; the
database alone opens no sealed value (see [`docs/security.md`](security.md#what-leaks-when)).

| Path | What it holds |
|---|---|
| `hyperdrop.db` | The SQLite database (WAL mode, `synchronous=FULL`): every account, token, share, file entry, folder, scheduled change, linked-share source and filter, gallery record, visitor row, push registration and the change journal. Its schema stamp is `PRAGMA user_version`. |
| `secret` | The volume secret: 32 random bytes, created on first boot (mode 0600). It is the server's identity (`serverID`), the key of every access cookie and the key every sealed value is derived from. A file that exists but cannot be read, or holds fewer than 32 bytes, refuses the boot rather than being replaced. Losing it makes clients refuse the server as a different install and leaves every sealed value unopenable. |
| `shares/<id>/files/<relpath>` | One plain file per committed upload, at the path the client sent. Nothing is deduplicated. |
| `shares/<id>/parts/` | Uploads in flight: `<sha256(relpath)>.part` and its `.ranges` sidecar. Never served. |
| `shares/<id>/poster.jpg`, `poster.slug`, `thumbs/<slug>.jpg` | A share's preview frame and gallery tiles: decoration, never file entries. |
| `domain` | The domain the server serves, as set at boot or changed through the API. |
| `ddns` | The free name's state and its bearer token, and a custom DDNS recipe with its provider credentials (mode 0600). |
| `certmagic/` | Certificates, keys and ACME account data. |
| `logs/server.log` | The server's own log, rotated at 10 MB with ten files kept. Read with `hyperdrop-server logs` or `GET /api/admin/log`. |
| `backups/hyperdrop-<UTC time>.db` | A copy of the database (`VACUUM INTO`) taken once a day by the housekeeping pass and before an update over the API; the newest three are kept. A database that fails its integrity check at boot is moved aside and the newest backup that passes is restored. |
| `recovered.json` | Present for a week after a boot restored the database from a backup; `GET /api/usage` reports it as `db-recovered`. |
| `web/` | The web client's installed bundles: `<version>-<build>/` per install, `current` naming the one `/app` serves; the one before it is kept and older ones are removed. |
| `update/` | Where a staged binary waits for the root updater (the Linux install sets `HYPERDROP_UPDATE_DIR` to it). |
| `admin-password.seed` | The installer's one-shot admin password seed, removed by the first boot or by `resetadmin`. |

**Schema.** A volume is served only at the schema stamp this binary knows (`metadb.SchemaVersion`).
A newer stamp refuses to start, so an older binary never misreads a newer volume; a stamp-0 file
that already holds tables is refused as a database this server did not create. A change the
previous release ignores (a nullable column, a table or index no statement of that release names)
is added at the same stamp by the serving process, so a rollback to the previous release still
serves the volume.

**Housekeeping.** One pass runs at startup and then every five minutes. It releases upload
reservations past their 15-minute life (a reservation's life restarts each time its share's
uploads have landed 64 MiB of new bytes since the last restart), applies scheduled password and expiry changes that are due,
deletes expired shares (rows first, then the directory), removes abandoned uploads, deletes shares
older than an hour that hold no committed file and show no recent upload activity (never a Receive Inbox, a linked share or a share
with a folder record), prunes change-journal rows older than 30 days and device-link rows a day after
their mint, runs `PRAGMA optimize` and takes the daily backup. At boot, before it listens, the server
also removes any `shares/<id>` directory no row names: the trace of a delete that crashed between
removing the rows and removing the directory.

## Operator subcommands

`hyperdrop-server <subcommand>` runs against `HYPERDROP_DATA` and exits without serving. The
installer runs them as the service account, so root never opens a file in a tree the service
controls.

| Subcommand | Does |
|---|---|
| `version` | Prints the version and exits; touches nothing. |
| `checkschema` | Opens the volume as it is (no recovery pass, nothing sealed) and runs the integrity check. Exit 0: this binary can serve it; 3: the volume is newer than this binary; 1: anything else. The installer runs it with the new binary before replacing a running server. In an empty directory it creates an empty database. |
| `checkdb` | The same check, printing `ok` on success. |
| `admins` | Prints each administrator's username, one per line; prints nothing and creates nothing when there is no database. |
| `resetadmin` | Sets the password of the administrator `HYPERDROP_ADMIN_USER` names (or the sole administrator) to the contents of the file `HYPERDROP_ADMIN_PASSWORD_FILE` names, which it removes once read, creating that administrator when the name is new, and signs out every device of that account. Shares are kept. |
| `auto-update [on\|off]` | Prints `on` or `off`, or turns automatic updates on or off on the volume, as an administrator's switch does. Runs beside the running server, as the account that owns the data; send that server `SIGUSR1` (`systemctl kill --kill-whom=main --signal=SIGUSR1 hyperdrop`) and a switch turned on checks for a release at once. Creates nothing when there is no database (exit 1). |
| `reset2fa <account>` | Clears the account's second factor and recovery codes. Run it with the service stopped. Prints `RESET2FA-DONE` or `RESET2FA-ALREADY-OFF`; exit 4 for an unknown account. |
| `logs [--tail N]` | Prints the last N lines (default 2000, at most 5000) of the server's log across its rotated files. |
| `verify-update <binary> <signature>` | Exits 0 only when the signature is a trusted release key's, names this binary's bytes and this host's architecture, and is not older than the running version (see [`docs/security.md`](security.md#updates)). |

Any other first argument starts the server.

## The Linux install

The one-line installer (`platforms/linux/install.sh.in`, generated by
`platforms/linux/build-installer.sh`) downloads the release binary for the host's architecture
(amd64 or arm64), refuses it unless its SHA-256 matches the one baked into the installer, and runs
the embedded provisioner, `core/provision/provision.sh`, which is the same script the HyperDrop
apps upload over SSH. The provisioner is idempotent: running it again updates the binary and keeps
the data. It needs systemd and nothing else; nothing is compiled and no package manager is used.

It installs:

- the binary at `/usr/local/bin/hyperdrop-server` (`/usr/local/bin` so that under SELinux it is
  labelled `bin_t`; the previous binary is kept as `.old` until the new one answers health);
- the system user `hyperdrop` and the data directory `/var/lib/hyperdrop` (0700, owned by the
  account the service runs as);
- `/etc/hyperdrop/server.env` (0600): `HYPERDROP_DATA`, `HYPERDROP_ADMIN_PASSWORD_FILE`,
  `HYPERDROP_ADMIN_USER`, `HYPERDROP_AUTO_UPDATE`, `HYPERDROP_IP`, `HYPERDROP_DOMAIN`, `HYPERDROP_DDNS_NAME`,
  `HYPERDROP_BEHIND_NAT`, `HYPERDROP_ALLOW_PRIVATE`, `HYPERDROP_ACME_EMAIL`, `HYPERDROP_ACME_CA` and
  `HYPERDROP_UPDATE_DIR=/var/lib/hyperdrop/update`. It names the password seed file and never holds
  the password;
- `/etc/systemd/system/hyperdrop.service`, running as `hyperdrop` with
  `AmbientCapabilities=CAP_NET_BIND_SERVICE` so it binds 80 and 443 without root, and sandboxed:
  `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, `NoNewPrivileges`, `ProtectSystem=strict` with
  only the data directory writable, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, the kernel,
  control-group, clock and hostname protections, `UMask=0077`, `LockPersonality`,
  `MemoryDenyWriteExecute`, `RestrictRealtime`, `RestrictSUIDSGID`, `RestrictNamespaces`,
  `SystemCallArchitectures=native`, `SystemCallFilter=@system-service` (`EPERM` otherwise),
  `RestrictAddressFamilies` to IPv4, IPv6, Unix and netlink, `InaccessiblePaths` over the host's
  D-Bus, systemd, Docker, containerd and Podman control sockets, `Restart=always` and
  `GOMEMLIMIT` at 60% of the host's memory (at least 128 MiB). A container image may switch some
  of these off for every service with a drop-in of its own (the linuxcontainers images' `lxc`
  generator turns off `NoNewPrivileges`, `ProtectKernelTunables` and `ProtectControlGroups`, and
  more in a privileged container); the unit then runs with the rest, the bounding set,
  `RestrictSUIDSGID`, the system call filter and `InaccessiblePaths` among them. On a host whose capability bounding
  set lacks `CAP_NET_BIND_SERVICE` (some unprivileged containers) the unit asks for no ambient
  capability and the service still runs as `hyperdrop`, binding 80 and 443 only where the host's
  `ip_unprivileged_port_start` lets any account bind them;
- the root updater: `hyperdrop-update.path` watches `update/staged.bin` and starts
  `hyperdrop-update.service`, which runs `/usr/local/lib/hyperdrop/update.sh` as root (see
  [`docs/security.md` § Updates](security.md#updates)).

On a volume with no administrator the admin password is written to
`/var/lib/hyperdrop/admin-password.seed` (0600, by the service account), which the first boot
reads and removes. The provisioner refuses to run over a server that already has an administrator
unless `HYPERDROP_RESET_ADMIN=1` asks it to reset that administrator's password, which it does
by writing the same seed file and running `resetadmin` with `HYPERDROP_ADMIN_PASSWORD_FILE` naming
it (`HYPERDROP_RESET_DOMAIN=1` alongside also forgets the stored domain, so `HYPERDROP_DOMAIN` applies
again). `HYPERDROP_UNINSTALL=1` removes the service, the updater and the binary;
`HYPERDROP_PURGE=1` with it also removes the data and the `hyperdrop` user. These and
`HYPERDROP_BIN_SHA256` (the expected SHA-256 of the uploaded `.gz`) are the provisioner's inputs;
the server itself does not read them.

Logs go to journald (`journalctl -u hyperdrop`) and to `logs/server.log` in the data directory.

## The Synology package

`platforms/synology/` builds one `.spk` per DSM generation (DSM 7, DSM 6.2) and CPU family. The
package runs the server as the package's own user, on the high ports the install wizard asked for
(`HYPERDROP_HTTP_ADDR=:5080` and `HYPERDROP_HTTPS_ADDR=:5443` unless changed), behind the router's
forwarded 80 and 443. Its start script sets `HYPERDROP_BEHIND_NAT=1`, `HYPERDROP_CHANNEL=synology`,
`HYPERDROP_PLATFORM=dsm7` or `dsm6`, and `HYPERDROP_LINKED_SCAN` to every mounted `/volumeN`, so the
shared folders the package user is granted (Control Panel, Shared Folder, Permissions) become the
roots a linked share may serve. The wizard's domain or free name, ports and optional
`HYPERDROP_TRUSTED_PROXIES` are kept in the package's `hyperdrop.conf`. Package Center updates the
package; the server's update route refuses on it.

## Running in a container

`server/Dockerfile` builds an image from the repository root
(`docker build -f server/Dockerfile -t hyperdrop-server .`) with `/data` as a volume and ports 80
and 443 exposed. Pass the variables with `-e`. A container has no root updater, so leave
`HYPERDROP_UPDATE_DIR` unset and update by replacing the image.
