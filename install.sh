#!/usr/bin/env bash
# ACSAC 2026 artifact -- one-shot setup.
#
# Installs Python dependencies, fetches the BinShot backbone, and puts the
# evaluation data in place. Safe to re-run.
#
# Environment:
#   PYTHON             python interpreter to use            (default: python3)
#                      (PINPOINT_PYTHON is accepted as an alias)
#   PINPOINT_DATA_URL  where to fetch the data bundle from  (see artifact/scripts/fetch_data.sh)
#   SKIP_DATA=1        skip the data download (data already staged by hand)
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ART="$ROOT/artifact"
PY="${PINPOINT_PYTHON:-${PYTHON:-python3}}"

echo "== 1/3  Python dependencies"
"$PY" -m pip install --quiet --upgrade pip
"$PY" -m pip install --quiet -r "$ROOT/requirements.txt"

# torch and torchvision have to match each other; installing either one over a
# mismatched partner breaks the backbone's import with a confusing error about
# torchvision::nms. Colab and most GPU images already ship a matched pair, so
# only install when one is actually missing, and let pip resolve the pair.
if ! "$PY" -c 'import torch, torchvision' >/dev/null 2>&1; then
    echo "    torch/torchvision not both present -- installing a matched pair"
    "$PY" -m pip install --quiet torch torchvision
else
    echo "    torch/torchvision already present -- left untouched"
fi
"$PY" - <<'PYEOF'
import torch
print(f"    torch {torch.__version__}  cuda={torch.cuda.is_available()}"
      + (f"  device={torch.cuda.get_device_name(0)}" if torch.cuda.is_available() else "  (running on CPU)"))
PYEOF

echo "== 2/3  BinShot backbone"
# The localization layer imports the BCSD backbone's model definitions. The
# backbone is third-party code, used unmodified, and is fetched rather than
# redistributed here. Only its Python sources are needed.
if [ -f "$ART/binshot/binshot.py" ]; then
    echo "    already present at artifact/binshot"
else
    rm -rf "$ART/binshot"
    git clone --depth 1 --filter=blob:none --no-checkout \
        https://github.com/asw0316/binshot.git "$ART/binshot" >/dev/null 2>&1
    git -C "$ART/binshot" sparse-checkout init --cone >/dev/null 2>&1
    git -C "$ART/binshot" sparse-checkout set --no-cone '/*.py' '/LICENSE' >/dev/null 2>&1
    git -C "$ART/binshot" checkout >/dev/null 2>&1
    echo "    cloned $(ls -1 "$ART/binshot"/*.py | wc -l) backbone sources into artifact/binshot"
fi

echo "== 3/3  Evaluation data"
if [ "${SKIP_DATA:-0}" = "1" ]; then
    echo "    SKIP_DATA=1 -- skipped"
else
    "$ART/scripts/fetch_data.sh"
fi

echo
echo "== precomputing reference embeddings"
# Without these the cascade recomputes each reference's embedding once per
# candidate function, which dominates the runtime. Takes a few seconds.
if [ -f "$ART/data/reference_embeddings/reference_embeddings_regular.pt" ]; then
    echo "    already present"
else
    "$PY" "$ART/precompute_reference_embeddings.py" --vuln_db regular fno_inline \
        --cuda "${CUDA:-0}" 2>&1 | grep -E "Saving|Done!" | sed 's/^/    /'
fi

echo
echo "== verifying layout"
missing=0
for f in \
    "$ART/binshot/binshot.py" \
    "$ART/models/binshot_sim.model" \
    "$ART/models/pretrain.all.corpus.voca" \
    "$ART/data/reference_db/default.json" \
    "$ART/data/reference_db/fno_inline.json" \
    "$ART/data/ground_truth/gt_ranges.json" \
    "$ART/data/ground_truth/ground_truth_v3.txt" \
    "$ART/data/ground_truth/subset.json" ; do
    if [ -e "$f" ]; then
        printf '    ok      %s\n' "${f#$ROOT/}"
    else
        printf '    MISSING %s\n' "${f#$ROOT/}"
        missing=1
    fi
done
n_expected=$("$PY" -c "import json;print(len(json.load(open('$ART/data/ground_truth/subset.json'))['binaries']))" 2>/dev/null || echo 0)
n_targets=$(ls -1 "$ART/data/targets"/*.json 2>/dev/null | wc -l)
if [ "$n_targets" -eq "$n_expected" ] && [ "$n_expected" -gt 0 ]; then
    printf '    ok      artifact/data/targets (%s binaries)\n' "$n_targets"
else
    printf '    MISSING artifact/data/targets (found %s of %s)\n' "$n_targets" "$n_expected"
    missing=1
fi

echo
if [ "$missing" -ne 0 ]; then
    echo "[!] setup incomplete -- see MISSING entries above"
    exit 1
fi
echo "[+] setup complete."
echo "    quick check (minutes) : bash artifact/scripts/smoke.sh"
echo "    claim 1 (hours)       : claims/claim1/run.sh"
echo "    claim 2 (seconds)     : claims/claim2/run.sh"
