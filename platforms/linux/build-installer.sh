#!/bin/sh
# Writes website/install.sh from platforms/linux/install.sh.in, the newest
# entry of the server manifest and the provisioner in
# core/provision/provision.sh. Pure sh plus python3 so the pipeline
# regenerates it on Linux and diffs the committed file, the way it diffs the
# feeds and the appcast. Deterministic: the same inputs write the same bytes.
#
#   build-installer.sh [--manifest FILE] [--out FILE]
#
# The architectures are the template's @SHA_<ARCH>@ placeholders, each filled
# with that build's SHA-256 from the manifest's newest entry. It needs nothing
# beyond these three files, so it runs the same in the standalone server
# repository, where there is no website tree: pass the published manifest
# (https://gethyperdrop.com/downloads/server/releases.json) as --manifest and
# a path of your own as --out.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
manifest="$root/website/downloads/server/releases.json"
out="$root/website/install.sh"
usage="usage: build-installer.sh [--manifest FILE] [--out FILE]"
while [ $# -gt 0 ]; do
  case "$1" in
    --manifest) manifest="${2:?$usage}"; shift 2 ;;
    --out) out="${2:?$usage}"; shift 2 ;;
    *) echo "$usage" >&2; exit 2 ;;
  esac
done
[ -f "$manifest" ] || { echo "build-installer.sh: no server manifest at $manifest; pass --manifest (the published one is https://gethyperdrop.com/downloads/server/releases.json)" >&2; exit 2; }
[ -d "$(dirname "$out")" ] || { echo "build-installer.sh: $(dirname "$out") does not exist; pass --out" >&2; exit 2; }
python3 - "$here/install.sh.in" "$root/core/provision/provision.sh" "$manifest" "$out" <<'PY'
import json, re, sys
template, provisioner, manifest, out = sys.argv[1:5]
text = open(template).read()
# One @SHA_<ARCH>@ placeholder per architecture the installer serves.
arches = sorted({a.lower() for a in re.findall(r"@SHA_([A-Z0-9]+)@", text)})
if not arches:
    sys.exit(f"{template} holds no @SHA_<ARCH>@ placeholder")
entry = json.load(open(manifest))["releases"][0]
linux = entry.get("linux") or {}
for arch in arches:
    sha = (linux.get(arch) or {}).get("sha256") or ""
    if not re.fullmatch(r"[0-9a-f]{64}", sha):
        sys.exit(f"{manifest}: {entry.get('version')} has no linux.{arch}.sha256: the Linux release has not measured it")
script = open(provisioner).read()
if "HYPERDROP_PROVISION_SH" in script:
    sys.exit("the provisioner contains the heredoc delimiter HYPERDROP_PROVISION_SH")
if not script.endswith("\n"):
    script += "\n"
for key, value in [("@VERSION@", entry["version"])] + [
        (f"@SHA_{arch.upper()}@", linux[arch]["sha256"]) for arch in arches]:
    if text.count(key) != 1:
        sys.exit(f"{template} must hold {key} exactly once")
    text = text.replace(key, value)
# The provisioner's as_svc, verbatim, for the installer's own preflight.
fn = re.search(r"^as_svc\(\) \{\n.*?^\}\n", script, re.S | re.M)
if not fn:
    sys.exit(f"{provisioner} defines no as_svc")
if text.count("@AS_SERVICE@\n") != 1:
    sys.exit(f"{template} must hold @AS_SERVICE@ on a line of its own, once")
text = text.replace("@AS_SERVICE@\n", fn.group(0))
if text.count("@PROVISIONER@\n") != 1:
    sys.exit(f"{template} must hold @PROVISIONER@ on a line of its own, once")
text = text.replace("@PROVISIONER@\n", script)
with open(out, "w") as f:
    f.write(text)
print(f"wrote {out} for {entry['version']}")
PY
sh -n "$out"
