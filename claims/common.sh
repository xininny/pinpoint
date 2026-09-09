# Shared helpers for the claim runners. Sourced, not executed.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ART="$ROOT/artifact"
PY="${PYTHON:-${PINPOINT_PYTHON:-python3}}"
CUDA="${CUDA:-0}"

# Where the two runs live. Both are reused if already present, so running the
# claims in either order costs one pass over the subset, not two.
CASCADE="$ART/results/cascade"
BASELINE="$ART/results/stage1"

run_pinpoint() {   # run_pinpoint <output_dir> [extra args...]
    local out="$1"; shift

    # pinpoint.py locks each target so several workers can share a GPU. A run
    # that dies -- a Colab disconnect, Ctrl-C -- leaves those locks behind, and
    # the recorded PID may have been reused by then, so the next run could read
    # a stale lock as live and skip that target silently. Clearing them is safe:
    # a target whose report already exists is skipped anyway.
    [ -d "$out" ] && find "$out" -name '*.lock' -delete 2>/dev/null

    # PYTHONUNBUFFERED: pinpoint.py reports each finished target through
    # tqdm.write, which goes to stdout. Piped to a log, stdout is block
    # buffered, so those lines would only appear when the run ends -- the cell
    # looks hung for hours. Unbuffered, they arrive as each target completes.
    PYTHONUNBUFFERED=1 "$PY" "$ART/pinpoint.py" --vuln_db regular fno_inline \
        --output_dir "$out" --cuda "$CUDA" "$@"
}

# A run restricted to one stage writes result_<target>_stageN.txt into a stageN/
# subdirectory. The analysis code expects result_<target>.txt directly under the
# database directory, so present the stage run in that shape without copying.
flatten_stage() {   # flatten_stage <run dir> <stage>
    local src="$1" stage="$2" dst="$1.flat"
    rm -rf "$dst"
    for db in regular fno_inline; do
        [ -d "$src/$db/stage$stage" ] || continue
        mkdir -p "$dst/$db"
        for f in "$src/$db/stage$stage"/result_*_stage$stage.txt; do
            [ -e "$f" ] || continue
            ln -sf "$f" "$dst/$db/$(basename "$f" | sed "s/_stage$stage\.txt\$/.txt/")"
        done
    done
    echo "$dst"
}

assert_no_skips() {   # assert_no_skips <log file>
    if grep -q 'locked=[1-9]' "$1" 2>/dev/null; then
        echo "[!] a target was skipped because it was locked by another run" >&2
        grep 'done: processed=' "$1" >&2
        return 1
    fi
    return 0
}

compare_expected() {   # compare_expected <actual> <expected>
    echo
    echo "--- comparison with the recorded reference output ---"
    if [ ! -f "$2" ]; then
        echo "    no reference output recorded at ${2#$ROOT/}"
        return 0
    fi
    if diff -u "$2" "$1" >/dev/null 2>&1; then
        echo "    identical to ${2#$ROOT/}"
    else
        diff -u "$2" "$1" | sed 's/^/    /' || true
        echo
        echo "    Scores are rounded to two decimals, so a different GPU can move"
        echo "    the last digit on a few windows. A changed accuracy by more than"
        echo "    a point, or a changed case count, is not expected."
    fi
}
