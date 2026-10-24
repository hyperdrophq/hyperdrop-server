#!/bin/sh
# Builds the Linux server binaries exactly as a HyperDrop release does: the
# release builds with this script, and so can anyone with the source, which
# is what makes a published binary checkable against it
# (docs/reproducible-builds.md in the public repository).
#
#   build-server.sh OUTDIR [ARCH...]     (ARCH: amd64, arm64; default both)
#
# Writes OUTDIR/hyperdrop-server-linux-<arch> and its .gz. Everything that
# changes the binary's bytes is fixed here rather than taken from the
# machine: the Go toolchain is exactly the version server/go.mod's go line
# names (GOTOOLCHAIN fetches it when the installed go differs, which needs
# go 1.21 or newer), every build variable is set (a go.work outside the
# checkout is ignored, GOWORK=off), the source path is trimmed,
# and no version-control stamp is linked, so the same source builds the same
# bytes in any checkout, on any machine. The .gz is not part of that promise:
# gzip implementations differ, so a binary is compared uncompressed.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=${1:?usage: build-server.sh OUTDIR [ARCH...]}
shift
[ $# -gt 0 ] || set -- amd64 arm64
mkdir -p "$out"
out=$(cd "$out" && pwd)

go_line=$(sed -n 's/^go \([0-9][0-9.]*\)$/\1/p' "$root/server/go.mod")
[ -n "$go_line" ] || { echo "build-server.sh: no go line in $root/server/go.mod" >&2; exit 1; }
toolchain="go$go_line"

GOTOOLCHAIN=$toolchain
GOWORK=off
CGO_ENABLED=0
GOOS=linux
GOFLAGS=
GOEXPERIMENT=
GOFIPS140=off
GOAMD64=v1
GOARM64=v8.0
export GOTOOLCHAIN GOWORK CGO_ENABLED GOOS GOFLAGS GOEXPERIMENT GOFIPS140 GOAMD64 GOARM64

have=$(cd "$root/server" && go env GOVERSION) || {
  echo "build-server.sh: go env GOVERSION failed; the build needs go 1.21 or newer to fetch $toolchain" >&2
  exit 1
}
[ "$have" = "$toolchain" ] || {
  echo "build-server.sh: the build runs on $have, not $toolchain (server/go.mod); the bytes would differ" >&2
  exit 1
}

for arch in "$@"; do
  case "$arch" in
    amd64 | arm64) ;;
    *) echo "build-server.sh: unknown architecture $arch (amd64, arm64)" >&2; exit 2 ;;
  esac
  bin="$out/hyperdrop-server-linux-$arch"
  echo "==> building hyperdrop-server linux/$arch with $toolchain"
  (cd "$root/server" && GOARCH="$arch" go build -trimpath -buildvcs=false \
    -ldflags='-s -w -X main.official=true' -o "$bin" .)
  # -n: no name and no timestamp in the header.
  gzip -9 -n -c "$bin" >"$bin.gz"
done
