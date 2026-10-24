# Reproducible builds

Every HyperDrop server release tagged in this repository rebuilds, byte for byte, into the Linux
binaries gethyperdrop.com publishes. So you can check that the server you download, or the one
already running on your box, is built from this source and nothing else. No key or account is
needed: the check compares SHA-256 sums.

## What it shows

- **The published binary is this source.** Each release tag (`v1.1.1` and so on) is the source the
  release was built from, and building it with `platforms/linux/build-server.sh` gives the same
  bytes as `hyperdrop-server-<version>-linux-<arch>.gz` on the
  [server page](https://gethyperdrop.com/downloads/server/), uncompressed.
- **The release signature names that binary.** Each download has a `.sig` beside it, the release
  signature a server checks before it installs an update (see
  [`docs/security.md`](security.md#updates)). It names the SHA-256 of the uncompressed binary, so
  the three sums (built, downloaded, signed) must be the same.
- **Your server runs it.** Every Linux install (Server Management, the one-line installer, Update
  Server in the apps and the server's own automatic update) installs that published binary at
  `/usr/local/bin/hyperdrop-server`, so its SHA-256 is the release's.

A tag is pushed only after the release's own source has been rebuilt and compared with the
signatures it published (below), so a tag that exists is one that rebuilds.

Not covered: the Synology packages (`.spk`, an archive with timestamps of its own, built without
the official stamp), the HyperDrop apps and the command line, which are not in this repository,
and releases older than the first tag, which were built with a version-control stamp naming a
commit that is not public.

## Check a release

You need Go 1.21 or newer (the build fetches the exact toolchain it pins, below), `curl`, `gzip`
and `sha256sum` or `shasum`.

```sh
git clone https://github.com/hyperdrophq/hyperdrop-server.git
cd hyperdrop-server
git checkout v1.1.1
platforms/linux/verify-release.sh 1.1.1
```

It builds both architectures, downloads the release and prints, for each architecture, the sum
of the binary built here, of the one published and the one the signature names, then `sums MATCH`
or `sums MISMATCH`. It also checks the release signature under the release keys, with the
server's own `verify-update`, for the architecture of the machine it runs on (an Apple silicon Mac
or an ARM64 Linux box checks arm64, an Intel or AMD one amd64), and says that the other
architecture's signature was not checked there. It exits 0 only when every sum matches and every
signature it checked is valid.

## Check your own server

On the box, see which version it runs and compare the installed binary:

```sh
/usr/local/bin/hyperdrop-server version
platforms/linux/verify-release.sh --installed /usr/local/bin/hyperdrop-server <that version>
```

Or run the check on another machine and compare its sums with `sha256sum
/usr/local/bin/hyperdrop-server` on the box.

## What the build pins

`platforms/linux/build-server.sh OUTDIR [amd64|arm64]` is the build HyperDrop's release runs. It
fixes everything that changes the bytes rather than taking it from the machine:

- the Go toolchain: exactly the version the `go` line of `server/go.mod` names, through
  `GOTOOLCHAIN` (an installed go 1.21 or newer downloads it from the Go project when it differs);
- `CGO_ENABLED=0`, `GOOS=linux`, `GOARCH`, `GOAMD64=v1`, `GOARM64=v8.0`, `GOFIPS140=off`,
  `GOWORK=off` (no Go workspace outside the checkout can replace a module), and an empty `GOFLAGS`
  and `GOEXPERIMENT`;
- `go build -trimpath -buildvcs=false -ldflags '-s -w -X main.official=true'`: no file paths of
  the machine that built it and no version-control stamp, so any checkout of the same source
  builds the same bytes. `main.official` marks a HyperDrop release, the only kind that installs
  newer releases on its own.

The same source builds the same binary on Linux or macOS, on amd64 or arm64. The `.gz` beside it
is not compared: gzip implementations differ.

## How a release is tagged

The release is built in HyperDrop's main repository with this same script, signed there (the
signing key never leaves the release machine) and published on gethyperdrop.com. When this
repository is next published, the commit that added the release's signatures is exported here and
rebuilt with `build-server.sh`, and each release signature must verify, under the release keys,
over the binary just built. Only when every architecture verifies is that tree pushed as the tag
`v<version>`; otherwise no tag is pushed and the publish fails. Every later publish rebuilds the
existing tag the same way and fails if it no longer reproduces the release. Before every publish, the project's CI also checks that this
repository's tree builds the same binaries as the main repository's.
