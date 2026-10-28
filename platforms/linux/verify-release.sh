#!/bin/sh
# Checks that a published HyperDrop server release is built from this source:
# builds the checkout with build-server.sh, downloads the release's binaries
# and signatures, and compares the three SHA-256 sums per architecture (the
# binary built here, the one published, the one the release signature names).
#
#   verify-release.sh [--installed PATH] [--base URL] VERSION
#
# Check out the release first (git checkout vVERSION): the checkout's server
# must be VERSION. --installed PATH also compares a binary installed on a box
# (a Linux install keeps it at /usr/local/bin/hyperdrop-server). --base is
# where the release is published (default https://gethyperdrop.com/downloads/server).
# The release signature of the published binary is checked under the release
# keys for this machine's architecture (the server's own verify-update: the
# binary built here on Linux, go run elsewhere); the other architecture's
# signature is named, not checked, and the output says so.
#
# Exit 0 when every sum matches and every signature checked is valid, 1 when
# one is not, 2 on a usage error.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
usage="usage: verify-release.sh [--installed PATH] [--base URL] VERSION"
installed=""
base="https://gethyperdrop.com/downloads/server"
version=""
while [ $# -gt 0 ]; do
  case "$1" in
    --installed) installed="${2:?$usage}"; shift 2 ;;
    --base) base="${2:?$usage}"; shift 2 ;;
    -h | --help) echo "$usage"; exit 0 ;;
    -*) echo "$usage" >&2; exit 2 ;;
    *) [ -z "$version" ] || { echo "$usage" >&2; exit 2; }; version=$1; shift ;;
  esac
done
[ -n "$version" ] || { echo "$usage" >&2; exit 2; }
base=${base%/}

have_version=$(sed -n 's/^const version = "\(.*\)"$/\1/p' "$root/server/main.go")
if [ "$have_version" != "$version" ]; then
  echo "verify-release.sh: this checkout is server $have_version, not $version; check out the release first: git checkout v$version" >&2
  exit 2
fi
for tool in curl gzip; do
  command -v "$tool" >/dev/null 2>&1 || { echo "verify-release.sh: needs $tool" >&2; exit 2; }
done
if command -v sha256sum >/dev/null 2>&1; then
  sum() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sum() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  echo "verify-release.sh: needs sha256sum or shasum" >&2
  exit 2
fi

host_arch=$(cd "$root/server" && GOWORK=off go env GOARCH)
host_os=$(cd "$root/server" && GOWORK=off go env GOOS)
# verify_signature BINARY SIG: the server's own verify-update, which checks
# the signature for the architecture it runs on.
verify_signature() {
  if [ "$host_os" = linux ]; then
    "$work/built/hyperdrop-server-linux-$host_arch" verify-update "$1" "$2"
  else
    (cd "$root/server" && GOWORK=off go run . verify-update "$1" "$2")
  fi
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
"$here/build-server.sh" "$work/built" amd64 arm64

failed=0
for arch in amd64 arm64; do
  name="hyperdrop-server-$version-linux-$arch.gz"
  curl -fsSL "$base/$name" -o "$work/$name" || { echo "verify-release.sh: could not download $base/$name" >&2; exit 1; }
  curl -fsSL "$base/$name.sig" -o "$work/$name.sig" || { echo "verify-release.sh: could not download $base/$name.sig" >&2; exit 1; }
  gzip -dc "$work/$name" >"$work/published-$arch"
  built=$(sum "$work/built/hyperdrop-server-linux-$arch")
  published=$(sum "$work/published-$arch")
  signed=$(sed -n 's/^sha256 \([0-9a-f]\{64\}\)$/\1/p' "$work/$name.sig")
  echo ""
  echo "linux/$arch"
  echo "  built from this source  $built"
  echo "  published binary        $published"
  echo "  release signature names ${signed:-nothing}"
  if [ "$built" = "$published" ] && [ "$published" = "$signed" ]; then
    echo "  sums MATCH"
  else
    echo "  sums MISMATCH"
    failed=1
  fi
  if [ "$arch" = "$host_arch" ]; then
    if verify_signature "$work/published-$arch" "$work/$name.sig"; then
      echo "  release signature valid under the release keys"
    else
      echo "  release signature INVALID"
      failed=1
    fi
  else
    echo "  release signature not checked here: verify-update checks only its own architecture, so run this on a $arch machine for it"
  fi
  eval "built_$arch=\$built"
done

if [ -n "$installed" ]; then
  mine=$(sum "$installed")
  echo ""
  echo "$installed"
  echo "  installed binary        $mine"
  # shellcheck disable=SC2154 # built_amd64 and built_arm64 are set by the eval above
  if [ "$mine" = "$built_amd64" ] || [ "$mine" = "$built_arm64" ]; then
    echo "  MATCH: it is server $version built from this source"
  else
    echo "  MISMATCH: it is not server $version as built from this source"
    failed=1
  fi
fi
exit "$failed"
