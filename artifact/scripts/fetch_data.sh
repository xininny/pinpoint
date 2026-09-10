#!/usr/bin/env bash
# Download the evaluation data bundle (target analysis output, reference
# databases, ground truth, the BinShot similarity model and its vocabulary)
# into artifact/.
#
# The bundle is archived with a DOI so that the artifact stays retrievable
# independently of this repository. Override the location with:
#
#   PINPOINT_DATA_URL=https://.../pinpoint-acsac26-data.tar.gz ./fetch_data.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ART_ROOT="$(cd "$HERE/.." && pwd)"
PY_BIN="${PYTHON:-${PINPOINT_PYTHON:-python3}}"

# Zenodo record for this artifact. Replace with the minted DOI URL.
DEFAULT_URL="https://zenodo.org/records/PLACEHOLDER/files/pinpoint-acsac26-data.tar.gz"
URL="${PINPOINT_DATA_URL:-$DEFAULT_URL}"
ARCHIVE="${TMPDIR:-/tmp}/pinpoint-acsac26-data.tar.gz"

# The bundle's contents are fixed, so its digest is too. Checked after every
# download, whatever the URL, so a truncated transfer or a stale mirror fails
# here rather than showing up later as an unexplained number.
EXPECTED_SHA256="f62131e4be6b5294375b8f85a5e62d4025ce576e3391e1f2f16ee5d663ad028a"

# Is what is on disk the subset this checkout declares? "The directory exists"
# is not enough: a checkout that pulled a different subset keeps the old
# binaries, and the run would then quietly evaluate them.
want=$("$PY_BIN" -c "import json;print(len(json.load(open('$ART_ROOT/data/ground_truth/subset.json'))['binaries']))" 2>/dev/null || echo 0)
have=$(ls -1 "$ART_ROOT/data/targets"/*.json 2>/dev/null | wc -l)

if [ -f "$ART_ROOT/models/binshot_sim.model" ] && [ "$want" -gt 0 ] && [ "$have" -eq "$want" ]; then
    echo "[=] data already present under $ART_ROOT ($have binaries) -- nothing to do"
    exit 0
fi

# Get the bundle and check it BEFORE touching anything on disk. Deleting first
# and failing afterwards would leave the tree unusable, which is worse than
# leaving stale data in place.
LOCAL="$(cd "$ART_ROOT/.." && pwd)/dist/pinpoint-acsac26-data.tar.gz"

if [ -f "$LOCAL" ]; then
    ARCHIVE="$LOCAL"
    echo "[*] using the bundle shipped with the repository"
else
    case "$URL" in
        *PLACEHOLDER*)
            cat >&2 <<'MSG'
[!] No data bundle found and no data URL configured.

    Expected dist/pinpoint-acsac26-data.tar.gz in the repository, or a URL:

        PINPOINT_DATA_URL=<url> artifact/scripts/fetch_data.sh
MSG
            exit 1
            ;;
    esac
    echo "[*] downloading $URL"
    if command -v curl >/dev/null 2>&1; then
        curl -fL --retry 3 -o "$ARCHIVE" "$URL"
    else
        wget -O "$ARCHIVE" "$URL"
    fi
fi

echo "[*] verifying checksum"
if command -v sha256sum >/dev/null 2>&1; then
    echo "$EXPECTED_SHA256  $ARCHIVE" | sha256sum -c -
elif command -v shasum >/dev/null 2>&1; then
    echo "$EXPECTED_SHA256  $ARCHIVE" | shasum -a 256 -c -
else
    echo "    no sha256sum/shasum available -- skipping verification" >&2
fi

if [ "$have" -gt 0 ] && [ "$have" -ne "$want" ]; then
    echo "[*] on disk: $have binaries; this checkout expects $want -- replacing"
    rm -rf "$ART_ROOT/data/targets" "$ART_ROOT/data/reference_db" \
           "$ART_ROOT/data/reference_embeddings"
    # results computed against the previous subset are no longer meaningful
    if [ -d "$ART_ROOT/results" ]; then
        echo "    clearing results from the previous subset"
        rm -rf "$ART_ROOT/results"
    fi
fi

echo "[*] unpacking into $ART_ROOT"
tar -xzf "$ARCHIVE" -C "$ART_ROOT"
[ "$ARCHIVE" = "$LOCAL" ] || rm -f "$ARCHIVE"

echo "[+] done: $(ls -1 "$ART_ROOT/data/targets"/*.json | wc -l) target binaries"
