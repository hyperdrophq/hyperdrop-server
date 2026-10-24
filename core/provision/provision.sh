#!/bin/sh
# HyperDrop server provisioner. Runs as root on the target VPS. Idempotent:
# safe to re-run for redeploys and upgrades (data lives in /var/lib/hyperdrop
# and survives).
#
# The payload is a PREBUILT static binary (CGO_ENABLED=0) uploaded by the
# client: nothing is compiled here, no package manager is touched, and no
# container runtime is installed. That is what makes this work the same on
# Ubuntu, Debian, RHEL-family, an EOL distro whose mirrors are gone, and
# inside an LXC container. The only host requirement is systemd.
#
# Inputs (env):
#   HYPERDROP_ADMIN_PASSWORD  required: first-boot admin password. It reaches
#                             the server as a one-shot seed file in the data
#                             directory (HYPERDROP_ADMIN_PASSWORD_FILE), which
#                             the first boot reads and removes; an existing
#                             admin always wins, except under
#                             HYPERDROP_RESET_ADMIN=1, where resetadmin reads
#                             and removes the same seed. Never written to
#                             server.env.
#   HYPERDROP_ADMIN_USER  optional: the first admin's username (3-32 of
#                             a-z 0-9 . _ -); empty means "admin". With
#                             HYPERDROP_RESET_ADMIN=1 it names the admin to
#                             reset (or to create beside the existing ones);
#                             empty then targets the sole admin.
#   HYPERDROP_AUTO_UPDATE  optional: 1 (or on, true) makes a NEW server install
#                             each release on its own; empty (or 0, off, false)
#                             leaves that off. The server records it only when
#                             it creates the volume's first administrator.
#   HYPERDROP_RESET_DOMAIN  with HYPERDROP_RESET_ADMIN=1, forget the domain and free
#                             name the volume stored so HYPERDROP_DOMAIN applies again
#   HYPERDROP_BIN_SHA256  optional: sha256 of the uploaded .gz; verified
#   HYPERDROP_DOMAIN      required: the custom domain; share pages serve on it
#                             and uploaded files on files.<domain>. Both need
#                             an A record. (HYPERDROP_ALLOW_PRIVATE=1 waives it
#                             for a development server: plain HTTP, one origin.)
#   HYPERDROP_IP          required with a domain: this server's public IPv4,
#                             the reference point for "does your DNS point here" 
#   HYPERDROP_DDNS_NAME   optional: a free <name>.hyperdrop.link address the
#                             server claims at boot, the alternative to a
#                             domain (set one or the other, never both)
#   HYPERDROP_BEHIND_NAT  optional: 1 = this box has no public IPv4 of its
#                             own; a router forwards 443 (and 80) to it and
#                             ACME arbitrates reachability
#   HYPERDROP_ACME_EMAIL  optional: ACME account email
#   HYPERDROP_ACME_CA     optional: ACME directory override (staging/tests)
#   HYPERDROP_UNINSTALL   optional: 1 = remove the service and binary
#   HYPERDROP_PURGE       optional: 1 = with UNINSTALL, also delete the data
#
# Expects the gzipped server binary at /tmp/hyperdrop-install/hyperdrop-server.gz
# (uploaded by the client, into a directory it created 0700 and owns).
#
# Progress protocol (parsed by the HyperDrop apps):
#   HYPERDROP-STEP:<n>:<label>   step <n> starting
#   HYPERDROP-DONE               success
#   HYPERDROP-FAIL:<label>       failure (also exits non-zero)

set -eu
# Every path here is absolute; / is a directory the service account can
# enter when a command drops to it.
cd /

# The staging directory the client created 0700 and owns; everything it
# uploaded lives here. This script deletes only the payload and the run wrapper
# (which holds HYPERDROP_ADMIN_PASSWORD in cleartext); the CLIENT removes
# STAGE_DIR itself, once it has read the log and exit files inside it. Removing
# the directory here would delete the channel this run reports through.
STAGE_DIR=/tmp/hyperdrop-install
BIN_GZ="$STAGE_DIR/hyperdrop-server.gz"
# /usr/local/bin, NOT a lib dir: on SELinux systems a binary under
# /usr/local/lib is labelled lib_t, the service stays in the init_t domain,
# and its OUTBOUND connections are denied, silently, because the denials are
# dontaudit'ed. Let's Encrypt then never issues a certificate. A bin_t binary
# transitions to unconfined_service_t, which works. (Verified on CentOS
# Stream 8 with SELinux enforcing.)
BIN=/usr/local/bin/hyperdrop-server
DATA_DIR=/var/lib/hyperdrop
# Where the SERVICE stages a replacement binary and where the root-owned
# installer below watches. Inside the data dir because that is the only place
# the hardened unit lets the service write.
UPDATE_DIR="$DATA_DIR/update"
# The root-owned installer the path unit runs.
UPDATER=/usr/local/lib/hyperdrop/update.sh
CONF_DIR=/etc/hyperdrop
ENV_FILE="$CONF_DIR/server.env"
UNIT=/etc/systemd/system/hyperdrop.service
SVC_USER=hyperdrop
# The admin password's seed file: written by the service account and read and
# removed by the server's first boot or by resetadmin.
SEED="$DATA_DIR/admin-password.seed"

# as_svc CMD... runs CMD as the service account whenever that account owns the
# data directory, so root never opens a file in a tree the service controls
# (a link planted there would otherwise aim a root write anywhere). It runs
# CMD as the caller where it does not: a box whose service runs as root, or
# a first install with no data yet. setpriv first, then runuser; a box with
# neither (busybox) runs CMD as the caller. The account and directory default
# to the installed ones, so the SSH clients run this same definition.
as_svc() {
    if [ "$(id -u)" = 0 ] && as_svc_uid=$(id -u "${SVC_USER:-hyperdrop}" 2>/dev/null) &&
        [ "$(stat -c %u "${DATA_DIR:-/var/lib/hyperdrop}" 2>/dev/null)" = "$as_svc_uid" ]; then
        if command -v setpriv >/dev/null 2>&1; then
            setpriv --reuid="$as_svc_uid" --regid="$(id -g "${SVC_USER:-hyperdrop}")" --clear-groups -- "$@"
            return
        fi
        if command -v runuser >/dev/null 2>&1; then
            runuser -u "${SVC_USER:-hyperdrop}" -- "$@"
            return
        fi
    fi
    "$@"
}

fail() {
    echo "HYPERDROP-FAIL:$1" >&2
    exit 1
}

# write_seed writes the admin password to $SEED byte for byte, as the service
# account and 0600, through stdin so it never appears in an argv.
write_seed() {
    # shellcheck disable=SC2016 # $1 is the inner shell's
    printf '%s' "$admin_password" |
        as_svc sh -c 'umask 077; cat > "$1.new" && mv -f "$1.new" "$1"' sh "$SEED" ||
        fail "could not write the admin password seed"
}

# ---------------------------------------------------------------- uninstall

if [ "${HYPERDROP_UNINSTALL:-}" = "1" ]; then
    [ "$(id -u)" = "0" ] || fail "must run as root"
    echo "HYPERDROP-STEP:1:uninstall"
    systemctl disable --now hyperdrop >/dev/null 2>&1 || true
    # The over-the-air update units are root-owned and would otherwise outlive
    # the uninstall, leaving a path unit watching a directory that is gone.
    systemctl disable --now hyperdrop-update.path >/dev/null 2>&1 || true
    rm -f "$UNIT" "$UNIT.old" /etc/systemd/system/hyperdrop-update.path \
          /etc/systemd/system/hyperdrop-update.service "$UPDATER"
    rmdir "$(dirname "$UPDATER")" 2>/dev/null || true
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed hyperdrop >/dev/null 2>&1 || true
    # Only our own files: INSTALL_DIR is /usr/local/bin, shared with the
    # rest of the system, so never remove the directory itself.
    rm -f "$BIN" "$BIN.old"
    rm -rf "$CONF_DIR"
    if [ "${HYPERDROP_PURGE:-}" = "1" ]; then
        # Only ever the directory this installer created, never a wildcard.
        # A data dir that is its own MOUNT (a block-storage volume, a ZFS
        # dataset) cannot be removed, only emptied: rm deletes everything
        # inside and then fails EBUSY on the mountpoint itself, which under
        # set -e aborted the uninstall right here. The fallback empties it;
        # a purge that genuinely cannot delete data still fails.
        rm -rf "$DATA_DIR" 2>/dev/null || \
            find "$DATA_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
        userdel "$SVC_USER" >/dev/null 2>&1 || true
    fi
    # Only the secrets and the payload. The log/exit/pid markers stay: the
    # client is still polling them to learn how this run ended, and the
    # client removes the whole directory once it has.
    rm -f "$STAGE_DIR/hyperdrop-server.gz" "$STAGE_DIR/hyperdrop-run.env"
    echo "HYPERDROP-DONE"
    exit 0
fi

# ---------------------------------------------------------------- preflight

echo "HYPERDROP-STEP:1:preflight"
[ "$(id -u)" = "0" ] || fail "must run as root"
[ -n "${HYPERDROP_ADMIN_PASSWORD:-}" ] || fail "HYPERDROP_ADMIN_PASSWORD not set"
# The password goes only into the seed file, and leaves the environment every
# command here inherits.
admin_password=$HYPERDROP_ADMIN_PASSWORD
unset HYPERDROP_ADMIN_PASSWORD
[ -f "$BIN_GZ" ] || fail "server binary missing at $BIN_GZ"
# The server refuses to boot on a choice it cannot read, so the install
# refuses it first, and server.env holds 1 or nothing.
case "${HYPERDROP_AUTO_UPDATE:-}" in
"" | 0 | off | false) HYPERDROP_AUTO_UPDATE= ;;
1 | on | true) HYPERDROP_AUTO_UPDATE=1 ;;
*) fail "HYPERDROP_AUTO_UPDATE is \"$HYPERDROP_AUTO_UPDATE\": use 1 to turn automatic updates on, or leave it empty" ;;
esac

# systemd is the one host dependency. Say so plainly rather than half
# installing and leaving a binary nothing ever starts.
[ -d /run/systemd/system ] || fail "no-systemd"
command -v systemctl >/dev/null 2>&1 || fail "no-systemd"
command -v gzip >/dev/null 2>&1 || fail "need gzip to unpack the server binary"
# The root updater reads a staged binary with GNU dd's no-following,
# non-blocking, byte-counted read, which BusyBox and BSD dd lack.
dd if=/dev/null of=/dev/null count=0 iflag=nofollow,nonblock,count_bytes 2>/dev/null ||
    fail "need GNU coreutils dd: the update installer reads a staged binary with iflag=nofollow,nonblock,count_bytes"

# An admin account that outlived the password which created it.
#
# EnsureAdmin only seeds on a FIRST boot, so re-provisioning a volume that
# already has one CANNOT change its password: the install then succeeds and the
# login that follows bounces, several minutes and a 5 MB upload later, with the
# owner told to use a password nobody has. Checked HERE, before any of that,
# because the answer does not change and the cost of learning it late is the
# whole run.
#
# HYPERDROP_RESET_ADMIN=1 is the fix rather than the refusal: whoever runs this
# already has root over SSH, which is strictly more authority than the account
# being reset, and every share on the volume is kept.
#
# An admin is whatever the server's own `admins` subcommand lists. The
# binary is the previous install's on a redeploy and absent on a first
# install, where there is nothing to list either way; the data directory is
# named because the server's default is a container path.
has_admin() {
    [ -x "$BIN" ] && as_svc env HYPERDROP_DATA="$DATA_DIR" "$BIN" admins 2>/dev/null | grep -q .
}
if has_admin && [ "${HYPERDROP_RESET_ADMIN:-}" != "1" ]; then
    fail "admin-exists"
fi

# Having systemd is not the same as being allowed to add a unit to it. On
# NixOS every /etc file is a read-only symlink into the store (units come
# from the system configuration, not from a script), and some appliance
# images mount /etc read-only too. Without this check the install runs to
# step 4 (user created, binary in place, schema stamped) and only then
# dies on the redirect with a bare "Read-only file system", leaving a
# half-install behind. Refuse up front, by name, having touched nothing.
probe="$(dirname "$UNIT")/.hyperdrop-write-probe"
if ! (: > "$probe") 2>/dev/null; then
    fail "systemd-readonly"
fi
rm -f "$probe"

# Integrity: a truncated upload must fail HERE, not as an exec-format error
# five steps later. Skipped (loudly) when the box has no sha256 tool.
if [ -n "${HYPERDROP_BIN_SHA256:-}" ]; then
    actual=""
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$BIN_GZ" | cut -d' ' -f1)
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$BIN_GZ" | cut -d' ' -f1)
    fi
    if [ -z "$actual" ]; then
        echo "no sha256 tool on this host: skipping upload integrity check"
    elif [ "$actual" != "$HYPERDROP_BIN_SHA256" ]; then
        fail "binary-corrupt"
    fi
fi

arch=$(uname -m 2>/dev/null || echo unknown)
case "$arch" in
    x86_64 | amd64 | aarch64 | arm64) : ;;
    *) fail "arch-unsupported" ;;
esac
echo "host: $(uname -s) $arch, systemd $(systemctl --version 2>/dev/null | head -1 | awk '{print $2}')"

# ------------------------------------------------------------------ install

echo "HYPERDROP-STEP:2:install"
# Binding :80/:443 as the unprivileged service user takes CAP_NET_BIND_SERVICE
# as an ambient capability, which systemd can grant only from the bounding set
# this box hands its processes. Some unprivileged containers drop it from that
# set entirely, and a unit that asks for it there never starts, so the
# bounding set decides: with the capability the service runs as $SVC_USER
# holding it alone; without it, as root holding no capability at all (the
# unit's bounding set keeps only the one this box lacks), binding the low
# ports wherever the box lets an unprivileged process bind them.
#
# bind_cap_bounded reads the set from /proc/self/status: CapBnd is a hex mask
# and CAP_NET_BIND_SERVICE is capability 10, so bit 10 of its last four hex
# digits (the whole mask can exceed the shell's integer range).
bind_cap_bounded() {
    bnd=$(awk '/^CapBnd:/ {print $2}' /proc/self/status 2>/dev/null)
    [ -n "$bnd" ] || return 1
    low=$bnd
    [ "${#bnd}" -gt 4 ] && low=${bnd#"${bnd%????}"}
    [ $(( 0x$low >> 10 & 1 )) = 1 ]
}
svc_user="$SVC_USER"
caps="AmbientCapabilities=CAP_NET_BIND_SERVICE"
if ! bind_cap_bounded; then
    echo "CAP_NET_BIND_SERVICE is not in this box's bounding set: running the service as root"
    svc_user=root
    caps=""
fi

if ! id -u "$SVC_USER" >/dev/null 2>&1; then
    # --system is portable across shadow-utils and busybox variants; fall
    # back to adduser for images that ship only that.
    useradd --system --no-create-home --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SVC_USER" >/dev/null 2>&1 ||
        useradd -r -M -d "$DATA_DIR" -s /bin/false "$SVC_USER" >/dev/null 2>&1 ||
        adduser -S -H -h "$DATA_DIR" "$SVC_USER" >/dev/null 2>&1 ||
        fail "could not create the $SVC_USER system user"
fi
# A new data directory belongs to the account the service runs as from the
# start, so every operator command below runs as that account and everything
# they create is the service's own.
if [ ! -d "$DATA_DIR" ]; then
    mkdir -p "$DATA_DIR"
    chown "$svc_user" "$DATA_DIR"
fi
mkdir -p "$(dirname "$BIN")" "$CONF_DIR"
chmod 0700 "$CONF_DIR"
chmod 0700 "$DATA_DIR"

gzip -dc "$BIN_GZ" > "$BIN.new" || fail "unpack server binary"
chmod 0755 "$BIN.new"
# NB: never run the binary bare to "smoke test" it: any argv it doesn't
# recognise means "serve", and it would block here forever. The schema step
# below exercises it with a subcommand that exits.
# Keep the outgoing binary: if the new one can't serve, step 5 puts it back.
if [ -f "$BIN" ]; then
    cp -f "$BIN" "$BIN.old"
fi
mv -f "$BIN.new" "$BIN"
# Give it the bin_t label (see the BIN comment above). restorecon is the
# right tool; chcon is the fallback; neither existing is fine (no SELinux).
restorecon -F "$BIN" >/dev/null 2>&1 || chcon -t bin_t "$BIN" >/dev/null 2>&1 || true

# ------------------------------------------------------------------- schema

echo "HYPERDROP-STEP:3:schema"
# Downgrade guard, run BEFORE the service is touched: data written by a NEWER
# server (exit 3) means this client is out of date: abort with the running
# server still serving.
rc=0
as_svc env HYPERDROP_DATA="$DATA_DIR" "$BIN" checkschema || rc=$?
if [ "$rc" != "0" ]; then
    # Restore the previous binary before bailing: the box keeps what worked.
    if [ -f "$BIN.old" ]; then mv -f "$BIN.old" "$BIN"; fi
    [ "$rc" = "3" ] && fail "app-outdated"
    fail "schema-check"
fi

# Reset the admin password on a volume that already had one. After the schema
# step, so the binary and the data are both known good, and before the service
# starts, so no window exists where the old password still works.
if has_admin && [ "${HYPERDROP_RESET_ADMIN:-}" = "1" ]; then
    echo "resetting the existing admin password"
    # resetadmin reads the seed and removes it, so the password is never in
    # an argv or an environment another local process could read.
    write_seed
    if ! as_svc env HYPERDROP_DATA="$DATA_DIR" HYPERDROP_ADMIN_PASSWORD_FILE="$SEED" "$BIN" resetadmin; then
        as_svc rm -f "$SEED"
        fail "admin-reset"
    fi
    # A reset that takes a new domain forgets the stored one and any free
    # name: the server persists both and the stored domain outranks
    # HYPERDROP_DOMAIN at boot, so without this the box keeps its old name.
    if [ "${HYPERDROP_RESET_DOMAIN:-}" = "1" ]; then
        echo "forgetting the previous domain"
        as_svc rm -f "$DATA_DIR/domain" "$DATA_DIR/ddns"
    fi
fi

# ------------------------------------------------------------------ service

echo "HYPERDROP-STEP:4:service"
umask 077
cat > "$ENV_FILE" <<EOF
HYPERDROP_DATA=$DATA_DIR
HYPERDROP_ADMIN_PASSWORD_FILE=$SEED
HYPERDROP_ADMIN_USER=${HYPERDROP_ADMIN_USER:-}
HYPERDROP_AUTO_UPDATE=${HYPERDROP_AUTO_UPDATE:-}
HYPERDROP_IP=${HYPERDROP_IP:-}
HYPERDROP_DOMAIN=${HYPERDROP_DOMAIN:-}
HYPERDROP_DDNS_NAME=${HYPERDROP_DDNS_NAME:-}
HYPERDROP_BEHIND_NAT=${HYPERDROP_BEHIND_NAT:-}
HYPERDROP_ALLOW_PRIVATE=${HYPERDROP_ALLOW_PRIVATE:-}
HYPERDROP_ACME_EMAIL=${HYPERDROP_ACME_EMAIL:-}
HYPERDROP_ACME_CA=${HYPERDROP_ACME_CA:-}
HYPERDROP_UPDATE_DIR=$UPDATE_DIR
EOF
chmod 0600 "$ENV_FILE"
umask 022

# keep_unit keeps the outgoing unit and the user it runs the service as, and
# restore_unit puts both back: the unit, the data directory owned by that
# user again, and systemd's view of it. A re-provision can change the service
# user (a box that ran as root gains the bind capability and moves to
# $SVC_USER, or the reverse), and the old binary under the new unit and
# ownership cannot serve, so the health rollback restores all three or the
# box restart-loops. Root reads the data whoever owns it; $SVC_USER reads
# only what it owns.
keep_unit() {
    old_user=""
    rm -f "$UNIT.old"
    [ -f "$UNIT" ] || return 0
    cp -f "$UNIT" "$UNIT.old" || return 0
    old_user=$(sed -n 's/^User=//p' "$UNIT.old" | tail -n 1)
    [ -n "$old_user" ] || old_user=root
}
restore_unit() {
    [ -f "$UNIT.old" ] || return 0
    mv -f "$UNIT.old" "$UNIT"
    if [ "$old_user" != "$svc_user" ]; then
        chown -R "$old_user" "$DATA_DIR" 2>/dev/null || true
    fi
    systemctl daemon-reload >/dev/null 2>&1 || true
}
keep_unit

# A re-provision that changes the service user (a box that ran as root gains
# the bind capability, or the reverse) re-owns the whole data directory to
# the new one, which the server cannot otherwise read ("open
# /var/lib/hyperdrop/secret: permission denied", a restart loop). Otherwise
# it is already the service's, operator commands included.
if [ "$(stat -c %u "$DATA_DIR")" != "$(id -u "$svc_user")" ]; then
    chown -R "$svc_user" "$DATA_DIR" ||
        echo "could not hand every file in $DATA_DIR to $svc_user; the health check decides"
fi
as_svc mkdir -p "$UPDATE_DIR"

# The first admin's password, for a volume that has no admin yet: written by
# the service account, 0600, and read and removed by the server's first
# boot, so it never sits in server.env or the service's environment. A volume
# with an admin already gets no seed (has_admin refused it in preflight, or
# resetadmin just set the password).
if ! has_admin; then
    write_seed
fi

# Soft Go memory ceiling, sized to the box: 60% of MemTotal with a 128 MiB
# floor. On the 0.5 GB hosts this app actually runs on, default GC headroom
# (heap grows to ~2x the live set) is the difference between fitting and the
# kernel OOM-killing the server mid-upload; measured at 300k shares the
# server sits at ~270 MB RSS without a limit and the index itself needs
# ~100-150 MB. A soft limit trades headroom for GC cycles, so the floor
# keeps it comfortably above any real live set on a small volume. Missing
# /proc/meminfo (never on systemd Linux, but belt and braces) falls back to
# 256 MiB.
mem_total_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)
if [ -n "$mem_total_kb" ]; then
    gomemlimit_mib=$((mem_total_kb * 60 / 100 / 1024))
    [ "$gomemlimit_mib" -lt 128 ] && gomemlimit_mib=128
else
    gomemlimit_mib=256
fi

cat > "$UNIT" <<EOF
[Unit]
Description=HyperDrop file share server
Documentation=https://github.com/hyperdrophq/hyperdrop-server
After=network-online.target
Wants=network-online.target
# Restart=always means always. The default rate limit (5 starts / 10 s) turns
# a TRANSIENT crash loop (a disk hiccup, a network blip during ACME) into a
# permanently dead server that only an SSH session can revive, which is the
# opposite of what this appliance owes its owner. RestartSec=2 already bounds
# the loop to one attempt every two seconds.
StartLimitIntervalSec=0

[Service]
Type=simple
User=$svc_user
ExecStart=$BIN
EnvironmentFile=$ENV_FILE
Environment=GOMEMLIMIT=${gomemlimit_mib}MiB
WorkingDirectory=$DATA_DIR
Restart=always
RestartSec=2
$caps
# The sandbox. Each directive holds in an unprivileged and a privileged LXC
# container (Proxmox, nesting on or off) and on a VM, from systemd 239 to
# 255: all of them have the mount namespace these need. A release older than
# a directive (ProtectHostname 242, ProtectKernelLogs 244, ProtectClock 245)
# logs it as unknown and runs without it, and a container image may switch
# some off for every service with a drop-in of its own (the linuxcontainers
# images' lxc generator turns off the kernel-tunable and cgroup ones, and in
# a privileged container the device, home and system ones too); the unit
# then runs with the rest. The server makes only @system-service calls
# (SQLite, uploads, zips, live relays), and a call outside the set fails
# with EPERM rather than killing it. It opens only IP, Unix and netlink
# sockets (netlink for its interface addresses), and never maps memory both
# writable and executable.
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ReadWritePaths=$DATA_DIR
# Everything the server writes is its own alone.
UMask=0077
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictNamespaces=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# ------------------------------------------------- over-the-air update unit
#
# The service CANNOT update itself and deliberately gains no privilege to: it
# runs as $svc_user under ProtectSystem=strict with only $DATA_DIR writable, so
# it can neither write $BIN nor call systemctl. What it CAN do is write a file.
#
# So: a path unit (root) watches for that file and a oneshot (root) does the
# swap. Restart=always then brings the service back on the new binary, which is
# why nothing here needs to signal the running process at all.
#
# Staging a binary must not be the same as root on this box: the API route and
# the service account can both write the staging directory. So the installer
# runs nothing it staged until the binary ALREADY installed (root-owned, the
# release public keys compiled in) has verified the release signature staged
# beside it (`hyperdrop-server verify-update`). The route additionally demands
# the admin password AND a second factor.
mkdir -p "$(dirname "$UPDATER")"
cat > "$UPDATER" <<'UPDEOF'
#!/bin/sh
# Installs a staged HyperDrop server binary. Run as root by hyperdrop-update.service.
set -eu
BIN=/usr/local/bin/hyperdrop-server
DATA_DIR=/var/lib/hyperdrop
STAGED=$DATA_DIR/update/staged.bin
# The largest staged binary and signature taken: the update route's and
# updatesig's own limits.
MAX_BIN=268435456
MAX_SIG=4096
[ -e "$STAGED" ] || [ -L "$STAGED" ] || exit 0

log() { echo "hyperdrop-update: $1"; }

# The service account owns the data directory and the staging directory in
# it, so it can re-point any path through either at any moment. Root enters
# the staging directory once, only when it is a real directory in its place,
# and names every staged file relative to it from then on: the working
# directory stays the directory entered, whatever the path names later. A
# link in its place is removed (rm without -r never removes a directory),
# which consumes the trigger; the service recreates the directory when it
# next stages.
cd -P "$DATA_DIR"
data=$(pwd -P)
if ! cd -P update 2>/dev/null || [ "$(pwd -P)" != "$data/update" ]; then
    rm -f "$data/update" 2>/dev/null || true
    log "staging directory refused: $DATA_DIR/update is not a directory"
    exit 0
fi

# A dd without that read would copy nothing, and every update would be
# refused as an empty file; the box says why instead, and the staged files
# are consumed all the same.
if ! dd if=/dev/null of=/dev/null count=0 iflag=nofollow,nonblock,count_bytes 2>/dev/null; then
    rm -rf staged.bin staged.sig
    log "staged binary ignored: this box's dd lacks iflag=nofollow,nonblock,count_bytes (GNU coreutils), so it cannot be read safely"
    exit 0
fi

# copy_staged NAME DEST MAX: copies at most MAX+1 bytes of NAME into the
# root-owned DEST, then answers 0 when DEST is a regular file of 1 to MAX
# bytes, 1 when it is not and 2 when the copy could not be written. dd opens
# NAME once, without following a link (a link to /dev/zero would be read
# without end) and without blocking (a FIFO with no writer would hold the
# unit until its timeout), so a link, a directory or a missing file copies
# nothing. Only DEST is checked, since nothing but root can change it. cp
# writes it: under SELinux this script's domain may not write a file through
# the shell's own redirection.
copy_staged() {
    dd if="$1" bs=65536 count=$(($3 + 1)) iflag=nofollow,nonblock,count_bytes 2>/dev/null |
        cp /dev/stdin "$2" 2>/dev/null || return 2
    [ -f "$2" ] && [ ! -L "$2" ] || return 1
    size=$(wc -c < "$2" | tr -d ' ')
    [ "$size" -ge 1 ] && [ "$size" -le "$3" ]
}

# Consume both FIRST, whatever happens next: a staged file that survives a
# failed install would be retried on every path-unit trigger, forever, so
# nothing between here and the removal may stop the script. What is verified
# below is the root-owned copy, so it is what gets installed, and the trap
# removes the copies on every exit. A signature that is missing or refused
# leaves TMPSIG empty, which verifies as unsigned.
TMP=$(mktemp /usr/local/bin/.hyperdrop-server.new.XXXXXX)
TMPSIG=$(mktemp /usr/local/bin/.hyperdrop-server.sig.XXXXXX)
trap 'rm -f "$TMP" "$TMPSIG"' EXIT
staged=0
copy_staged staged.bin "$TMP" "$MAX_BIN" || staged=$?
copy_staged staged.sig "$TMPSIG" "$MAX_SIG" || cp /dev/null "$TMPSIG" 2>/dev/null || true
rm -rf staged.bin staged.sig
case "$staged" in
1)
    log "staged binary refused: not a regular file of 1 to $MAX_BIN bytes"
    exit 0
    ;;
2)
    log "staged binary could not be copied for verification (is the disk full?); ignoring it"
    exit 0
    ;;
esac

# The release signature decides, checked by the binary already installed and
# BEFORE anything staged executes.
if ! "$BIN" verify-update "$TMP" "$TMPSIG"; then
    log "staged binary refused: no valid HyperDrop release signature for this host"
    rm -f "$TMP" "$TMPSIG"
    exit 0
fi
rm -f "$TMPSIG"

if ! head -c 4 "$TMP" | od -An -tx1 | tr -d ' \n' | grep -qi '^7f454c46'; then
    log "staged file is not an ELF binary, ignoring"
    rm -f "$TMP"
    exit 0
fi
chmod 0755 "$TMP"
# The new binary must at least RUN here before it replaces a working one.
# `version` prints and exits, serving nothing and touching no volume: any
# argument the server does not understand would instead fall through and start
# a server, and this script would hang holding the update forever.
if ! "$TMP" version >/dev/null 2>&1; then
    log "staged binary does not run on this host, ignoring"
    rm -f "$TMP"
    exit 0
fi

NEW_VERSION=$("$TMP" version 2>/dev/null || true)

cp -f "$BIN" "$BIN.old" 2>/dev/null || true
OLD_VERSION=$("$BIN.old" version 2>/dev/null || true)
mv -f "$TMP" "$BIN"
# Outside /usr/local/bin a binary is labelled lib_t and SELinux denies the
# service's outbound connections SILENTLY (no certificate, no explanation), so
# the label is forced back exactly as the install step does.
command -v restorecon >/dev/null 2>&1 && restorecon "$BIN" 2>/dev/null || true

log "installed a new binary, restarting"
systemctl restart hyperdrop || true

# Healthy means SERVING, not merely active: the health route is asked over
# HTTP (served unredirected on :80, the provisioned default) and must report
# the expected version, so a process that binds and wedges, or an old binary
# still flapping in and out, never passes as the new one. `is-active` alone
# cannot tell any of those apart. The window outlasts the binary's own 60 s
# boot self-check, so a wedged start has already exited (and flapped) before
# this gives up.
probe_health() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --max-time 2 http://127.0.0.1:80/api/health 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- -T 2 http://127.0.0.1:80/api/health 2>/dev/null
    else
        # No HTTP client on the box: degrade to process liveness.
        systemctl is-active --quiet hyperdrop && printf '"version":"%s"' "$1"
    fi
}

wait_healthy() { # $1 = version to require, $2 = seconds to wait
    i=0
    while [ "$i" -lt "$2" ]; do
        if probe_health "$1" | grep -q "\"version\":\"$1\""; then
            return 0
        fi
        i=$((i + 1))
        sleep 1
    done
    return 1
}

if wait_healthy "$NEW_VERSION" 90; then
    log "update complete: $NEW_VERSION is serving"
    exit 0
fi

# The old binary is known good: it is the one that was serving a moment ago.
if [ -f "$BIN.old" ]; then
    log "new binary never served, rolling back"
    mv -f "$BIN.old" "$BIN"
    command -v restorecon >/dev/null 2>&1 && restorecon "$BIN" 2>/dev/null || true
    systemctl restart hyperdrop || true
    if wait_healthy "$OLD_VERSION" 90; then
        log "rollback complete: $OLD_VERSION is serving again"
    else
        log "rollback restarted the old binary but it has not answered health yet"
    fi
fi
UPDEOF
chmod 0755 "$UPDATER"

# A oneshot has no start timeout of its own. The installer's longest honest
# run is two 90 s health waits, so ten minutes ends only a run that hangs.
cat > /etc/systemd/system/hyperdrop-update.service <<EOF
[Unit]
Description=Install a staged HyperDrop server binary
[Service]
Type=oneshot
ExecStart=$UPDATER
TimeoutStartSec=10min
EOF

# PathExists rather than PathChanged: the file is created by an atomic rename,
# and PathExists re-triggers for as long as it is there, so a trigger that
# races the rename still fires once the file is really in place.
cat > /etc/systemd/system/hyperdrop-update.path <<EOF
[Unit]
Description=Watch for a staged HyperDrop server binary
[Path]
PathExists=$UPDATE_DIR/staged.bin
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload || fail "systemctl daemon-reload"
systemctl enable hyperdrop >/dev/null 2>&1 || fail "systemctl enable"
systemctl enable --now hyperdrop-update.path >/dev/null 2>&1 || \
    echo "hyperdrop-update.path could not be enabled; updates will need SSH"
systemctl restart hyperdrop || fail "systemctl restart"

# ------------------------------------------------------------------- health

echo "HYPERDROP-STEP:5:health"
probe_health() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsS http://127.0.0.1/api/health >/dev/null 2>&1
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- http://127.0.0.1/api/health >/dev/null 2>&1
    else
        # No HTTP client on the box: fall back to systemd's own view.
        systemctl is-active --quiet hyperdrop
    fi
}

i=0
while [ $i -lt 30 ]; do
    i=$((i + 1))
    sleep 1
    if probe_health; then
        rm -f "$BIN.old" "$UNIT.old"
        # Only the secrets and the payload. The log/exit/pid markers stay: the
        # client is still polling them to learn how this run ended, and the
        # client removes the whole directory once it has.
        rm -f "$STAGE_DIR/hyperdrop-server.gz" "$STAGE_DIR/hyperdrop-run.env"
        echo "HYPERDROP-DONE"
        exit 0
    fi
done

journalctl -u hyperdrop -n 20 --no-pager >&2 2>/dev/null || true

# An UPDATE that can't serve must not leave the box worse than it was: put
# the previous binary and unit back and restart it.
if [ -f "$BIN.old" ]; then
    echo "new server did not become healthy: rolling back to the previous binary" >&2
    mv -f "$BIN.old" "$BIN"
    restore_unit
    # A binary that exits on start burns through systemd's start limit
    # (5 attempts / 10 s by default) long before the 30 s health budget is
    # up, leaving the unit in `failed`, and then `systemctl restart` answers
    # "start request repeated too quickly" and the rollback silently does
    # NOTHING. Clear the counter first, or the safety net drops the box.
    systemctl reset-failed hyperdrop >/dev/null 2>&1 || true
    systemctl restart hyperdrop >/dev/null 2>&1 || true
    fail "health-rollback"
fi
fail "health check timed out"
