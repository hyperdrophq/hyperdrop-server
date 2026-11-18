#!/bin/sh
# gen.sh <SecLists file> [output]
#
# Writes the embedded common-password list (default: commonpw.txt beside this
# script) from the SecLists file SOURCE names, and prints the input's SHA-256.
# The filter, in rank order:
#   1. ASCII-lowercase each line.
#   2. Keep lines of 8 to 72 printable ASCII bytes.
#   3. Drop lines matching platforms/opensource/private-patterns.txt, ignoring case.
#   4. Keep the first occurrence of each line.
#   5. Take the first 10000.
#   6. Sort in byte order.
#
# It needs the monorepo's private-patterns file and refuses before writing
# anything without it. The list is written to a temporary file and moved over
# the output only when it holds exactly 10000 lines, so a stage that fails
# mid-pipeline never leaves a short or empty list behind. (head ends the
# pipeline early, which pipefail would read as a failure of the stages
# before it, so the line count is the check.)
set -eu
export LC_ALL=C

here=$(cd "$(dirname "$0")" && pwd)
src=${1:?usage: gen.sh <SecLists file> [output]}
out=${2:-$here/commonpw.txt}
patterns=$here/../../../platforms/opensource/private-patterns.txt
want=10000

if [ ! -r "$src" ]; then
	echo "gen.sh: cannot read the source $src" >&2
	exit 1
fi
if [ ! -f "$patterns" ] || [ ! -r "$patterns" ]; then
	echo "gen.sh: cannot read $patterns; the list is generated only in the monorepo" >&2
	exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
	sum=$(sha256sum "$src" | cut -d' ' -f1)
else
	sum=$(shasum -a 256 "$src" | cut -d' ' -f1)
fi

tmp=$(mktemp "$out.XXXXXX")
trap 'rm -f "$tmp"' EXIT
tr 'A-Z' 'a-z' <"$src" |
	grep -E '^[ -~]{8,72}$' |
	grep -v -i -E -f "$patterns" |
	awk '!seen[$0]++' |
	head -n "$want" |
	sort >"$tmp"

lines=$(wc -l <"$tmp" | tr -d ' ')
if [ "$lines" != "$want" ]; then
	echo "gen.sh: the filter kept $lines lines, want $want; $out is left as it was" >&2
	exit 1
fi
chmod 644 "$tmp"
mv "$tmp" "$out"
trap - EXIT

echo "$sum"
