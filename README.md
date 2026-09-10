# PinPoint Artifact - ACSAC 2026

Artifacts for the paper "Localizing Vulnerabilities under Function Inlining Toward Precise Binary Patching" (ACSAC 2026).

## Overview

This artifact contains the implementation and evaluation code for PinPoint, a vulnerability localization system that works when the compiler has inlined the vulnerable function away. Once a vulnerable callee is absorbed into a larger caller, it no longer survives as a routine with a boundary, and binary code similarity detection (BCSD) models, which operate at function granularity, miss it. PinPoint adds a backbone-agnostic search layer on top of a pre-trained BCSD model: it ranks the candidate functions of a target binary and reports the byte range of the vulnerable code inside the one it retrieves.

The evaluation uses BinShot as the BCSD backbone:

- **BinShot**: BCSD model from S. Ahn, S. Ahn, H. Koo, and Y. Paek, "Practical binary code similarity detection with BERT-based transferable similarity learning," ACSAC 2022. Used with its published weights, without fine-tuning.

## System Requirements

- Python 3.9 - 3.12 (verified on 3.11 and on 3.12, which is Colab's version)
- CUDA-compatible GPU (2GB+ VRAM is enough; a Colab T4 is what this was sized for)
- 4GB+ system RAM, ~600MB disk
- A GPU is required. The pipeline embeds hundreds of thousands of sliding windows, and Colab's two CPU cores would take days.

## Installation

```bash
./install.sh
```

This script will:
- Install the Python dependencies
- Clone the BinShot backbone from its public repository
- Download the packaged data (target analysis output, reference database, ground truth, model weights)
- Precompute the reference embeddings
- Verify the layout

No disassembler is needed at evaluation time. Recovering functions, basic blocks and normalized tokens with Ghidra, and extracting the ground truth from DWARF, is done offline and shipped as JSON so that reviewers do not repeat a multi-day preprocessing stage.

## Quick Start

A smoke test first, to confirm the setup works before committing to the long run:

```bash
bash artifact/scripts/smoke.sh
```

Then the two reproducibility claims:

### Claim 1: Type II Function Retrieval
```bash
cd claims/claim1
./run.sh
```

### Claim 2: Vulnerability Range Localization
```bash
cd claims/claim2
./run.sh
```

Run claim 1 first. Claim 2 reuses its cascade results and then finishes in seconds.

## Expected Results

Each claim prints a table and compares itself against `claims/claim*/expected/result.txt`.

Claim 1 reproduces Table III, the type-wise Top-K retrieval accuracy and MRR, for two
configurations of the same subset: whole-function matching alone (the backbone standalone) and
PinPoint's full cascade. Claim 2 reproduces Table IV, the fraction of Top-1 queries whose
reported range overlaps the DWARF-derived vulnerable bytes.

Top-1 accuracy on this subset, against the paper's full-corpus figures:

| | Type I | Type II | Type III | Type IV | Overall |
|---|---|---|---|---|---|
| BinShot, this subset | 79.4% | 39.4% | 99.1% | 46.4% | 63.9% |
| PinPoint, this subset | 77.5% | 63.8% | 99.6% | 78.6% | **72.8%** |
| PinPoint, paper | 76.1% | 65.5% | 88.3% | 69.6% | **72.9%** |

Range localization on this subset, against the paper:

| | Type I | Type II | Type III | Type IV | Total |
|---|---|---|---|---|---|
| this subset | 100.0% | 70.3% | 100.0% | 95.2% | 85.9% |
| paper | 100.0% | 77.3% | 100.0% | 94.9% | 94.0% |

## Technical Notes

Due to computational constraints for artifact evaluation:

- The full corpus is 300 target binaries against a 577-entry reference database, and a complete
  run takes about a week on a single GPU. The packaged subset is 59 binaries, chosen so that all
  four inlining types appear in usable numbers.
- Binaries were selected on inlining type, project and measured runtime only, never on whether
  PinPoint got a case right. Type II accuracy varies widely by project, so its project mix is
  matched to the corpus; Type IV exists in only 19 binaries corpus-wide and the four cheapest
  are included. `artifact/scripts/build_eval_subset.py` carries the rule.
- Results show numerical differences from the paper but demonstrate the same trends. Overall
  Top-1 lands within 0.1 points and Type IV localization within 0.3; Type III retrieval and
  Type II localization drift the most, since 59 binaries do not average out the variation
  within a project.

## Directory Structure

```
artifact/                   # Main implementation code
  pinpoint.py               # Entry point; runs the cascade over a corpus
  backbone.py               # Model loading, tokenization, containment rule
  size_based_pruning.py     # Pre-cascade size filter
  stage1_whole_function.py  # Stage 1: whole-function comparison
  stage2_block_stride.py    # Stage 2: block-stride search
  stage3_token_stride.py    # Stage 3: token-stride search
  evaluate.py               # Range localization scoring (claim 2)
  analysis/                 # The paper's own Top-K table code (claim 1)
  scripts/                  # Smoke test, data fetch, subset derivation
  data/                     # Targets, reference DBs, ground truth
  models/                   # BinShot similarity model and vocabulary

claims/                     # Reproducibility claims
  claim1/                   # Type II function retrieval
  claim2/                   # Vulnerability range localization

infrastructure/             # Colab link and platform requirements
install.sh                  # Installation script
README.txt                  # This file
license.txt                 # MIT License, including third-party
use.txt                     # Usage guidelines and limitations
paper.pdf                   # The paper
PinPoint_AE_ACSAC.ipynb      # Colab notebook
```

## Running Individual Experiments

```bash
cd artifact

# one project, one stage
python3 pinpoint.py --project libtiff --stage 3

# turn off size-based pruning and watch the candidate count grow
python3 pinpoint.py --no-filter --overwrite

# the full type-wise Top-K tables, not just Type II
python3 analysis/topk_table.py --db-dir results/cascade --out /tmp/topk.txt
```

Every window scored in Stages 2 and 3 is dumped to `results/cascade/<db>/result_<target>_windows.jsonl.gz`, one JSON object per line, so a run can be inspected window by window. `python3 pinpoint.py --help` lists the rest.

## Evaluation Time

| | time |
|---|---|
| Smoke test | a few minutes |
| Claim 1 (two configurations) | about 6 hours on a Colab T4 |
| Claim 2 (reuses claim 1's run) | seconds |

Measured on a free Colab T4. The work is not GPU-bound, so a T4 is not much slower here than a datacentre GPU. Runs are resumable: a target whose report already exists is skipped, so re-running a claim after a dropped Colab session continues instead of starting over. Mounting Google Drive in the notebook keeps results across sessions.

## Troubleshooting

**`operator torchvision::nms does not exist` on import.** torch and torchvision are from different builds. Reinstall them together, or let Colab's preinstalled pair stand; `install.sh` will not touch them when both are already present.

**A target is skipped and the totals show `locked=1`.** A previous run died and left a lock file. The claim runners clear stale locks automatically; if you invoked `pinpoint.py` directly, delete `results/**/*.lock`.

**The run is very slow.** Check that a GPU is actually attached (`torch.cuda.is_available()`), and that `artifact/data/reference_embeddings/` exists. Without the precomputed embeddings the cascade recomputes each reference's embedding once per candidate function.

**Out of disk on Colab.** The data bundle plus results need roughly 600MB. Clearing `artifact/results/` between runs frees the largest part.

## Full Corpus

The complete evaluation corpus, 300 target binaries and their -fno-inline builds, a 577-entry reference database over 73 CVEs from nine projects, together with the raw outputs of the paper's own run, is archived separately with a DOI. A web interface that visualizes the per-query results is also available. `artifact/scripts/build_eval_subset.py` takes an explicit binary list, so the subset can be widened or the whole corpus reproduced.

## Contact

For questions about this artifact, please refer to the paper or contact the authors through the conference proceedings.
