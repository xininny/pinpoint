#!/usr/bin/env bash
#
# smoke.sh -- a few minutes end to end, to confirm the pipeline works.
#
# Runs the cheapest binaries of the packaged subset through the full cascade and
# scores them. The numbers it prints come from far too little data to compare
# against the paper -- this only answers "does it run and produce reports".
#
set -euo pipefail

ART="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-${PINPOINT_PYTHON:-python3}}"
OUT="$ART/results/smoke"
WORK="$OUT/targets"

mapfile -t SMOKE < <("$PY" - "$ART" <<'PYEOF'
import json, os, sys
with open(os.path.join(sys.argv[1], 'data', 'ground_truth', 'subset.json')) as f:
    print('\n'.join(json.load(f)['smoke']))
PYEOF
)

echo "== smoke set: ${#SMOKE[@]} binaries"
rm -rf "$WORK"; mkdir -p "$WORK"
for b in "${SMOKE[@]}"; do
    for d in targets targets_fno_inline; do
        [ -f "$ART/data/$d/$b.json" ] && ln -sf "$ART/data/$d/$b.json" "$WORK/$b.json" && break
    done
done
ls -1 "$WORK" | sed 's/^/   /'

echo
echo "== running the cascade"
[ -d "$OUT" ] && find "$OUT" -name '*.lock' -delete 2>/dev/null || true
"$PY" "$ART/pinpoint.py" --vuln_db regular fno_inline \
    --data_dir "$WORK" --output_dir "$OUT" --cuda "${CUDA:-0}" --overwrite 2>&1 \
    | grep -vE '^Run ' | tail -8

echo
echo "== scoring (numbers are not comparable to the paper at this size)"
"$PY" "$ART/evaluate.py" --results "$OUT" --label "smoke" | tail -18

echo
echo "[+] smoke test finished -- the pipeline runs end to end"
