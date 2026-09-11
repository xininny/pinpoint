#!/usr/bin/env bash
# fetch_safe_model.sh -- obtain SAFE's published weights and vocabulary.
#
# SAFE is released without a license: its repository carries a copyright notice
# and no grant, so its weights cannot be redistributed in this artifact the way
# BinShot's can. They are fetched from the authors' own distribution instead.
#
# Two files end up in artifact/models/safe/:
#   safe_trained_X86.pb   the frozen graph (210 MiB)
#   word2id.json          the instruction vocabulary (15 MiB), which arrives
#                         inside a 420 MiB i2v archive; the rest of that
#                         archive is the training-time embedding matrix, which
#                         inference does not use, and is discarded.
set -euo pipefail

ART_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ART_ROOT/models/safe"
PY_BIN="${PINPOINT_PYTHON:-${PYTHON:-python3}}"
TMP="${TMPDIR:-/tmp}/pinpoint-safe"

MODEL_ID="1Kwl8Jy-g9DXe1AUjUZDhJpjRlDkB4NBs"
I2V_ID="1CqJVGYbLDEuJmJV6KH4Dzzhy-G12GjGP"

# What the authors' distribution served when this artifact was prepared. A
# mismatch is reported but not treated as fatal: we do not control these files
# and cannot tell an upstream update from a corrupted download.
MODEL_SHA256="442ba07ca3402fff3ed7d3b2b8c7427a3f7ef209e22b8f262de5ffa823caaf17"
WORD2ID_SHA256="a41c8f667f31d83fcd2c3753eb319bfb2bd5d8690320b36251c428b84bf88380"

mkdir -p "$OUT" "$TMP"

check() {   # check <file> <expected sha256> <label>
    command -v sha256sum >/dev/null 2>&1 || return 0
    local got
    got="$(sha256sum "$1" | cut -d' ' -f1)"
    if [ "$got" = "$2" ]; then
        echo "    $3: checksum ok"
    else
        echo "    $3: checksum differs from the copy this artifact was prepared with." >&2
        echo "       expected $2" >&2
        echo "       got      $got" >&2
        echo "       SAFE's distribution may have been updated. Results may shift." >&2
    fi
}

if [ -s "$OUT/safe_trained_X86.pb" ] && [ -s "$OUT/word2id.json" ]; then
    echo "    already present at artifact/models/safe"
    exit 0
fi

if ! "$PY_BIN" -c 'import gdown' >/dev/null 2>&1; then
    "$PY_BIN" -m pip install --quiet gdown
fi

if [ ! -s "$OUT/safe_trained_X86.pb" ]; then
    echo "    downloading the SAFE model (210 MiB)"
    "$PY_BIN" -m gdown "$MODEL_ID" -O "$OUT/safe_trained_X86.pb" --quiet
    check "$OUT/safe_trained_X86.pb" "$MODEL_SHA256" "model"
fi

if [ ! -s "$OUT/word2id.json" ]; then
    echo "    downloading the SAFE vocabulary (inside a 420 MiB archive)"
    "$PY_BIN" -m gdown "$I2V_ID" -O "$TMP/i2v.tar.bz2" --quiet
    # Take only word2id.json; the embedding matrix beside it is training data.
    tar -xjf "$TMP/i2v.tar.bz2" -C "$TMP"
    found="$(find "$TMP" -name word2id.json -print -quit)"
    if [ -z "$found" ]; then
        echo "[!] word2id.json not found inside the i2v archive" >&2
        exit 1
    fi
    mv "$found" "$OUT/word2id.json"
    rm -rf "$TMP"
    check "$OUT/word2id.json" "$WORD2ID_SHA256" "vocabulary"
fi

echo "    SAFE weights in artifact/models/safe"
