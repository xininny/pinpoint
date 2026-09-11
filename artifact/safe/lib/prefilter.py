#!/usr/bin/env python3
"""
Shared target/vuln size-ratio pre-filter, applied identically across all
baseline reproduction pipelines (HermesSim / VulHawk / trex / B7_safe).

Same rule and threshold as the post-hoc analysis filter in
artifact/analysis/topk_table.py and BinShot's own live filter
(artifact/size_based_pruning.py): drop a (vuln, target) pair if
target_size / vuln_size < PREFILTER_RATIO, where "size" is each model's own
natural function-size metric (token count for trex/BinShot, instruction
count for SAFE, node/block count for HermesSim/VulHawk) — the filter is a
relative ratio, so the specific unit doesn't matter as long as it's used
consistently within one model.

Value re-derived 2026-08-03 from the GT-only ratio boxplot
(the ground-truth size distribution, see the paper's Section VI
copy.txt): Type 1 (pure V) IQR-Tukey lower fence = 0.540, vs the old 0.622
which was dropping more genuine GT matches than necessary.
"""

PREFILTER_RATIO = 0.540


def passes(target_size: int, vuln_size: int) -> bool:
    if vuln_size <= 0:
        return True
    return target_size / vuln_size >= PREFILTER_RATIO
