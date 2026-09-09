#!/usr/bin/env bash
# Claim 1 -- Type II retrieval. See claim.txt.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../common.sh"
OUT="$HERE/actual"; mkdir -p "$OUT"

echo "== running PinPoint's full cascade over the subset"
run_pinpoint "$CASCADE" > "$OUT/run.cascade.log" 2>&1
grep -vE '^Run ' "$OUT/run.cascade.log" | tail -5 || true
assert_no_skips "$OUT/run.cascade.log"

echo
echo "== running the same subset with Stage 1 only (whole-function matching)"
run_pinpoint "$BASELINE" --stage 1 > "$OUT/run.stage1.log" 2>&1
grep -vE '^Run ' "$OUT/run.stage1.log" | tail -5 || true
assert_no_skips "$OUT/run.stage1.log"

BASE_FLAT="$(flatten_stage "$BASELINE" 1)"

echo
echo "== computing type-wise Top-K tables"
"$PY" "$ART/analysis/topk_table.py" --db-dir "$CASCADE"   --out "$OUT/topk.cascade.txt"  2>&1 | tail -2
"$PY" "$ART/analysis/topk_table.py" --db-dir "$BASE_FLAT" --out "$OUT/topk.baseline.txt" 2>&1 | tail -2

echo
set +e
"$PY" "$ART/analysis/report_claim1.py" \
    --cascade "$OUT/topk.cascade.txt" --baseline "$OUT/topk.baseline.txt" | tee "$OUT/claim1.txt"
rc=${PIPESTATUS[0]}
set -e

compare_expected "$OUT/claim1.txt" "$HERE/expected/result.txt"
echo
echo "== claim 1: $([ $rc -eq 0 ] && echo PASS || echo FAIL)"
exit $rc
