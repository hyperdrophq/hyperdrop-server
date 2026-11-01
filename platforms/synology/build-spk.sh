#!/bin/bash
# Builds one .spk per DSM generation and architecture. An .spk is a plain
# tar: INFO, package.tgz (the payload), scripts/, conf/, wizard dirs, icons.
# Version comes from server/main.go, the contract's single source; the
# generations, the families and the INFO arch each one declares come from
# arches.tsv.
#
# One script tree serves both generations: build_one stamps the generation
# into scripts/common (@DSM@), and a generation with its own privilege or
# resource file (dsm<major>/privilege, dsm<major>/resource) ships that one
# instead of conf/privilege or conf/resource.
#
# HYPERDROP_SPK_CHANGELOG, when set, is the package's changelog: this
# version's release notes as one line of plain text (platforms/synology/
# release.sh passes the server manifest's notes). Unset, the changelog is
# empty.
#
# HYPERDROP_LINUX_SERVER_DIR, when set, holds the linux server binaries
# platforms/release.sh built once (platforms/lib.sh, build_linux_servers); a
# family whose GOARCH is among them takes that binary instead of a build.
#
# The script needs only server/ and this directory, so it runs the same in
# the standalone server repository.
set -euo pipefail
cd "$(dirname "$0")"
VERSION=$(sed -n 's/^const version = "\(.*\)"$/\1/p' ../../server/main.go)
[ -n "$VERSION" ] || { echo "could not read the version from server/main.go" >&2; exit 1; }
OUT="${1:-dist}"
mkdir -p "$OUT"

# md5one FILE: the file's MD5 as hex, with macOS md5 or GNU md5sum.
md5one() {
    md5 -q "$1" 2>/dev/null || md5sum "$1" | cut -d' ' -f1
}

build_one() { # $1 = DSM major, $2 = filename/feed family, $3 = GOARCH, $4 = GOARM or -, $5 = INFO arch list, $6 = os_min_ver
    local major="$1" syno="$2" goarch="$3" goarm="$4" info_arch="$5" osmin="$6"
    [ "$goarm" != "-" ] || goarm=""
    local work
    work=$(mktemp -d)
    # shellcheck disable=SC2064 # expanded when the trap is set, on purpose
    trap "rm -rf '$work'" EXIT
    mkdir -p "$work/payload/bin"
    # The port-config .sc rides the payload: its resource entry resolves the
    # protocol-file inside the package target.
    mkdir -p "$work/payload/port_conf"
    cp port_conf/hyperdrop.sc "$work/payload/port_conf/"
    # DSM 7's main-menu page: the url app ui/config names, its CGI (the
    # server's dsmpage subcommand) and the icons DSM draws for it, made from
    # the package icons. DSM 6 gets no page: its authenticate.cgi does not
    # run as the package user, so the page could not check the DSM user.
    if [ "$major" = "7" ]; then
        mkdir -p "$work/payload/ui/images"
        cp ui/config ui/index.cgi "$work/payload/ui/"
        chmod 755 "$work/payload/ui/index.cgi"
        for size in 16 32 64; do
            cp PACKAGE_ICON.PNG "$work/payload/ui/images/icon_$size.png"
        done
        cp PACKAGE_ICON_256.PNG "$work/payload/ui/images/icon_256.png"
    fi
    # The licences of what the binary links ride beside it.
    cp ../../server/THIRD-PARTY-NOTICES.txt "$work/payload/bin/"
    local prebuilt="${HYPERDROP_LINUX_SERVER_DIR:-}/hyperdrop-server-linux-$goarch"
    if [ -n "${HYPERDROP_LINUX_SERVER_DIR:-}" ] && [ -z "$goarm" ] && [ -s "$prebuilt" ]; then
        cp "$prebuilt" "$work/payload/bin/hyperdrop-server"
    else
        (cd ../../server && env CGO_ENABLED=0 GOOS=linux "GOARCH=$goarch" \
            ${goarm:+"GOARM=$goarm"} \
            go build -trimpath -ldflags='-s -w' \
            -o "$work/payload/bin/hyperdrop-server" .)
    fi
    # --no-xattrs: macOS tar otherwise records each file's extended
    # attributes as pax headers that a NAS's tar does not know.
    tar --no-xattrs -czf "$work/package.tgz" -C "$work/payload" .
    local sum
    sum=$(md5one "$work/package.tgz")
    cp -R scripts conf WIZARD_UIFILES \
        PACKAGE_ICON.PNG PACKAGE_ICON_256.PNG "$work/"
    # The wizards are generated per generation from WIZARD_UIFILES/install_uifile
    # (wizards.py); DSM sees only the scripts, never the static source.
    rm -f "$work/WIZARD_UIFILES/install_uifile"
    python3 wizards.py "$major" "$work/WIZARD_UIFILES"
    if [ -f "dsm$major/privilege" ]; then
        cp "dsm$major/privilege" "$work/conf/privilege"
    fi
    if [ -f "dsm$major/resource" ]; then
        cp "dsm$major/resource" "$work/conf/resource"
    fi
    sed -e "s/@DSM@/$major/" scripts/common > "$work/scripts/common"
    sed -e "s/@VERSION@/$VERSION/" -e "s/@ARCH@/$info_arch/" \
        -e "s/@CHECKSUM@/$sum/" -e "s/@OSMIN@/$osmin/" \
        INFO.in > "$work/INFO"
    if [ "$major" = "7" ]; then
        printf '%s\n' 'dsmuidir="ui"' 'dsmappname="SYNO.SDS._ThirdParty.App.hyperdrop"' >> "$work/INFO"
    fi
    # The package's own changelog, HYPERDROP_SPK_CHANGELOG quoted the way
    # INFO wants. $ and the backquote are dropped rather than escaped:
    # whatever reads INFO, neither can then expand.
    HYPERDROP_SPK_CHANGELOG="${HYPERDROP_SPK_CHANGELOG:-}" python3 - "$work/INFO" <<'PY'
import os, sys
info = sys.argv[1]
text = os.environ["HYPERDROP_SPK_CHANGELOG"].replace("$", "").replace("`", "")
text = text.replace("\\", "\\\\").replace('"', '\\"')
body = open(info).read().replace("@CHANGELOG@", text)
open(info, "w").write(body)
PY
    local spk="$OUT/hyperdrop-$VERSION-dsm$major-$syno.spk"
    (cd "$work" && tar --no-xattrs -cf - INFO package.tgz scripts conf WIZARD_UIFILES \
        PACKAGE_ICON.PNG PACKAGE_ICON_256.PNG) > "$spk"
    echo "built $spk"
    rm -rf "$work"
    trap - EXIT
}

builds=$(python3 arches.py families)
while IFS=$'\t' read -r major syno goarch goarm info_arch osmin; do
    build_one "$major" "$syno" "$goarch" "$goarm" "$info_arch" "$osmin"
done <<< "$builds"

# Verify: members present, binaries static, checksum honest, every
# placeholder stamped, and each package's generation the one its name says.
# Each listing is read whole before it is searched: under pipefail, a reader
# that stops at its first match (grep -q) leaves tar writing into a closed
# pipe, and the SIGPIPE fails the check on a slow enough machine.
for spk in "$OUT"/hyperdrop-"$VERSION"-*.spk; do
    members=$(tar -tf "$spk")
    grep -qx 'INFO' <<<"$members" || { echo "$spk: no INFO" >&2; exit 1; }
    grep -qx 'package.tgz' <<<"$members" || { echo "$spk: no payload" >&2; exit 1; }
    # DSM reads the uninstall wizard (the delete-data choice) from this exact
    # path; anywhere else it uninstalls without asking.
    grep -qx 'WIZARD_UIFILES/uninstall_uifile' <<<"$members" \
        || { echo "$spk: no WIZARD_UIFILES/uninstall_uifile" >&2; exit 1; }
    # DSM runs the wizard scripts, which print the kept settings as defaults;
    # the static install_uifile would shadow them with a fixed wizard.
    listing=$(tar -tvf "$spk")
    for w in install_uifile.sh upgrade_uifile.sh; do
        grep -qx "WIZARD_UIFILES/$w" <<<"$members" \
            || { echo "$spk: no WIZARD_UIFILES/$w" >&2; exit 1; }
        grep -E "^-[r-][w-]x.* WIZARD_UIFILES/$w\$" <<<"$listing" >/dev/null \
            || { echo "$spk: WIZARD_UIFILES/$w is not executable" >&2; exit 1; }
    done
    if grep -qx 'WIZARD_UIFILES/install_uifile' <<<"$members"; then
        echo "$spk: the static WIZARD_UIFILES/install_uifile ships" >&2; exit 1
    fi
    # preinst is what refuses a fresh install the server cannot start from;
    # without it an empty wizard installs a package that never starts.
    grep -qx 'scripts/preinst' <<<"$members" \
        || { echo "$spk: no scripts/preinst" >&2; exit 1; }
    v=$(mktemp -d)
    # shellcheck disable=SC2064 # expanded when the trap is set, on purpose
    trap "rm -rf '$v'" EXIT
    tar -xf "$spk" -C "$v"
    tar -xzf "$v/package.tgz" -C "$v" ./bin/hyperdrop-server ./bin/THIRD-PARTY-NOTICES.txt \
        || { echo "$spk: the payload lacks the binary or its notices" >&2; exit 1; }
    kind=$(file "$v/bin/hyperdrop-server")
    grep -q 'statically linked' <<<"$kind" \
        || { echo "$spk: binary not static" >&2; exit 1; }
    want=$(sed -n 's/^checksum="\(.*\)"$/\1/p' "$v/INFO")
    got=$(md5one "$v/package.tgz")
    [ "$want" = "$got" ] || { echo "$spk: checksum mismatch" >&2; exit 1; }
    if grep -rq '@[A-Z_]*@' "$v/INFO" "$v/scripts" "$v/WIZARD_UIFILES"; then
        echo "$spk: an unstamped placeholder is left" >&2; exit 1
    fi
    major=$(basename "$spk" | sed -n 's/.*-dsm\([0-9]*\)-.*/\1/p')
    grep -q "^DSM_MAJOR=\"$major\"$" "$v/scripts/common" \
        || { echo "$spk: scripts/common is not stamped for DSM $major" >&2; exit 1; }
    grep -q "^os_min_ver=\"$major\." "$v/INFO" \
        || { echo "$spk: os_min_ver is not DSM $major" >&2; exit 1; }
    if [ "$major" = "6" ] && grep -q wizard_shared_folder "$v/WIZARD_UIFILES/install_uifile.sh"; then
        echo "$spk: a DSM 6 package asks for a shared folder" >&2; exit 1
    fi
    if [ "$major" = "7" ] && ! grep -q wizard_shared_folder "$v/WIZARD_UIFILES/install_uifile.sh"; then
        echo "$spk: a DSM 7 package does not ask for a shared folder" >&2; exit 1
    fi
    if [ "$major" = "7" ] && ! grep -q '"data-share"' "$v/conf/resource"; then
        echo "$spk: a DSM 7 package lacks the data-share resource" >&2; exit 1
    fi
    if [ "$major" = "6" ] && grep -q '"data-share"' "$v/conf/resource"; then
        echo "$spk: a DSM 6 package carries the data-share resource" >&2; exit 1
    fi
    # The DSM page: DSM 7 packages carry the app, its executable CGI, its
    # icons and the INFO keys that point DSM at them; DSM 6 packages none.
    payload=$(tar -tzvf "$v/package.tgz")
    if [ "$major" = "7" ]; then
        for f in ui/config ui/images/icon_16.png ui/images/icon_32.png \
            ui/images/icon_64.png ui/images/icon_256.png; do
            grep -E "^-.* \./$f\$" <<<"$payload" >/dev/null \
                || { echo "$spk: the payload lacks $f" >&2; exit 1; }
        done
        grep -E '^-[r-][w-]x.* \./ui/index\.cgi$' <<<"$payload" >/dev/null \
            || { echo "$spk: the payload lacks an executable ui/index.cgi" >&2; exit 1; }
        grep -qx 'dsmuidir="ui"' "$v/INFO" \
            || { echo "$spk: INFO lacks dsmuidir" >&2; exit 1; }
        grep -qx 'dsmappname="SYNO.SDS._ThirdParty.App.hyperdrop"' "$v/INFO" \
            || { echo "$spk: INFO lacks dsmappname" >&2; exit 1; }
    else
        if grep -E ' \./ui(/|$)' <<<"$payload" >/dev/null; then
            echo "$spk: a DSM $major package carries the DSM page" >&2; exit 1
        fi
        if grep -qE '^dsm(uidir|appname)=' "$v/INFO"; then
            echo "$spk: a DSM $major INFO names the DSM page" >&2; exit 1
        fi
    fi
    rm -rf "$v"
    trap - EXIT
done
echo "all packages verified"
