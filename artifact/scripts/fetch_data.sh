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

# "Already there" is not enough: a checkout whose subset has changed leaves a
# stale data directory behind, and the run would then quietly evaluate the old
# binaries. Compare what is on disk against the subset the checkout declares.
want=$("$PY_BIN" -c "import json;print(len(json.load(open('$ART_ROOT/data/ground_truth/subset.json'))['binaries']))" 2>/dev/null || echo 0)
have=$(ls -1 "$ART_ROOT/data/targets"/*.json 2>/dev/null | wc -l)

if [ -f "$ART_ROOT/models/binshot_sim.model" ] && [ "$want" -gt 0 ] && [ "$have" -eq "$want" ]; then
    echo "[=] data already present under $ART_ROOT ($have binaries) -- nothing to do"
    exit 0
fi

if [ "$have" -gt 0 ] && [ "$have" -ne "$want" ]; then
    echo "[*] target directory holds $have binaries but this checkout expects $want"
    echo "    replacing the stale data"
    rm -rf "$ART_ROOT/data/targets" "$ART_ROOT/data/reference_db" \
           "$ART_ROOT/data/reference_embeddings" "$ART_ROOT/models"
    # results computed against the old subset are no longer meaningful
    if [ -d "$ART_ROOT/results" ]; then
        echo "    clearing results from the previous subset"
        rm -rf "$ART_ROOT/results"
    fi
fi

# The bundle ships inside the repository, so a clone is self-contained and no
# download is needed. The archival copy on Zenodo is what the URL below points
# at, for anyone who has the code without the bundle.
LOCAL="$(cd "$ART_ROOT/.." && pwd)/dist/pinpoint-acsac26-data.tar.gz"
if [ -f "$LOCAL" ]; then
    echo "[*] using the bundle shipped with the repository"
    echo "[*] verifying checksum"
    if command -v sha256sum >/dev/null 2>&1; then
        echo "$EXPECTED_SHA256  $LOCAL" | sha256sum -c -
    elif command -v shasum >/dev/null 2>&1; then
        echo "$EXPECTED_SHA256  $LOCAL" | shasum -a 256 -c -
    fi
    echo "[*] unpacking into $ART_ROOT"
    tar -xzf "$LOCAL" -C "$ART_ROOT"
    echo "[+] done"
    ls -1 "$ART_ROOT/data/targets" | head -5
    echo "    ($(ls -1 "$ART_ROOT/data/targets" | wc -l) target binaries)"
    exit 0
fi

case "$URL" in
    *PLACEHOLDER*)
        cat >&2 <<'MSG'
[!] No data URL configured.

    The bundle location has not been baked into this checkout. Set it
    explicitly and re-run:

        PINPOINT_DATA_URL=<url to pinpoint-acsac26-data.tar.gz> \
            artifact/scripts/fetch_data.sh

    The bundle unpacks to  data/{reference_db,targets}  and
    models/{binshot_sim.model,pretrain.all.corpus.voca}  under artifact/.
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

echo "[*] verifying checksum"
if command -v sha256sum >/dev/null 2>&1; then
    echo "$EXPECTED_SHA256  $ARCHIVE" | sha256sum -c -
elif command -v shasum >/dev/null 2>&1; then
    echo "$EXPECTED_SHA256  $ARCHIVE" | shasum -a 256 -c -
else
    echo "    no sha256sum/shasum available -- skipping verification" >&2
fi

echo "[*] unpacking into $ART_ROOT"
tar -xzf "$ARCHIVE" -C "$ART_ROOT"
rm -f "$ARCHIVE"

echo "[+] done"
ls -1 "$ART_ROOT/data/targets"
