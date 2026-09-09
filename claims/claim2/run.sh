#!/usr/bin/env bash
# Claim 2 -- Type II vulnerability range localization. See claim.txt.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../common.sh"
OUT="$HERE/actual"; mkdir -p "$OUT"

echo "== running PinPoint's full cascade over the subset"
run_pinpoint "$CASCADE" 2>&1 | tee "$OUT/run.log"
assert_no_skips "$OUT/run.log"

echo
echo "== scoring the reported ranges against the DWARF ground truth"
set +e
"$PY" "$ART/evaluate.py" --results "$CASCADE" --label "packaged subset" \
    --json "$OUT/claim2.json" | tee "$OUT/claim2.txt"
rc=${PIPESTATUS[0]}
set -e

compare_expected "$OUT/claim2.txt" "$HERE/expected/result.txt"
echo
echo "== claim 2: $([ $rc -eq 0 ] && echo PASS || echo FAIL)"
exit $rc
