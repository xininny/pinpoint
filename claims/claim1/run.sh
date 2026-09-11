#!/usr/bin/env bash
# Claim 1 -- function retrieval under compiler inlining. See claim.txt.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../common.sh"
OUT="$HERE/actual"; mkdir -p "$OUT"

echo "== BinShot: full cascade over the subset"
run_pinpoint "$CASCADE" 2>&1 | tee "$OUT/run.binshot.cascade.log"
assert_no_skips "$OUT/run.binshot.cascade.log"

echo
echo "== BinShot: the same subset with Stage 1 only (whole-function matching)"
run_pinpoint "$BASELINE" --stage 1 2>&1 | tee "$OUT/run.binshot.stage1.log"
assert_no_skips "$OUT/run.binshot.stage1.log"

echo
echo "== SAFE: full cascade over the subset"
run_safe "$SAFE_CASCADE" 2>&1 | tee "$OUT/run.safe.cascade.log"

echo
echo "== SAFE: the same subset with Stage 1 only"
run_safe "$SAFE_BASELINE" --stage 1 2>&1 | tee "$OUT/run.safe.stage1.log"

BS_FLAT="$(flatten_stage "$BASELINE" 1)"
SF_FLAT="$(flatten_stage "$SAFE_BASELINE" 1)"

echo
echo "== computing type-wise Top-K tables"
for spec in "$CASCADE:binshot.cascade" "$BS_FLAT:binshot.stage1" \
            "$SAFE_CASCADE:safe.cascade" "$SF_FLAT:safe.stage1"; do
    "$PY" "$ART/analysis/topk_table.py" --db-dir "${spec%%:*}" \
        --out "$OUT/topk.${spec##*:}.txt" 2>&1 | tail -2
done

echo
"$PY" "$ART/analysis/report_claim1.py" \
    --binshot-baseline "$OUT/topk.binshot.stage1.txt" \
    --binshot-cascade  "$OUT/topk.binshot.cascade.txt" \
    --safe-baseline    "$OUT/topk.safe.stage1.txt" \
    --safe-cascade     "$OUT/topk.safe.cascade.txt" | tee "$OUT/claim1.txt"
