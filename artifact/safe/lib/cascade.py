#!/usr/bin/env python3
"""
Shared Stage 1->2->3 cascade logic, mirroring
artifact/pinpoint.py's rank_targets_for_query():
  - Stage 1 is skipped entirely when the query involves inlining (comparing
    a small inlined fragment against a target's whole truncated body
    dilutes the signal too much to be meaningful) -- Stage 2 always runs in
    that case instead. The caller decides this via `skip_stage1`, driven by
    the vuln entry's own `start_stage` field (1 or 2; set by the
    corpus build, see provenance.txt):
      - db='fno_inline': every row has start_stage=2 by construction -- the
        fno_inline vuln db only contains rows belonging to (project,
        filename, func_name) groups where at least one of the 8 compiler/
        opt configs showed inlining evidence in the regular build.
      - db='regular': the vuln entry's own `start_stage` field. This is a
        GROUP-level decision, not per-row: if ANY of a func's 8 configs
        shows inlining evidence (label V-V/V-NV, or absorption into
        another function), start_stage=2 for EVERY config of that func
        (even ones that are individually clean 'V'), otherwise 1.
  - Stage 2 runs unless Stage 1 ran and scored >= EARLY_EXIT_THRESHOLD.
  - Stage 3 runs unless Stage 2 scored >= EARLY_EXIT_THRESHOLD.
  - best_stage = whichever of the stages that actually ran has the max score.

stage1_fn/stage2_fn/stage3_fn are zero-arg callables so cascade_score() only
pays for the (real model forward pass) cost of stages that actually need to
run. stage1_fn returns a float score; stage2_fn/stage3_fn return
(score, meta_dict) so window/compared-range info can flow into the report.
"""

EARLY_EXIT_THRESHOLD = 0.99


def cascade_score(skip_s1: bool, stage1_fn, stage2_fn, stage3_fn, force_stage=None):
    """force_stage=1: run ONLY stage1 for every candidate, ignoring skip_s1
    entirely (including the flagged/inlined ones that would normally skip
    straight to stage2) -- for the "what if everything went through stage1"
    sweep. No stage2/3 calls happen in this mode. force_stage=None (default)
    is the normal skip_s1-driven cascade, unchanged."""
    scores = {}
    meta = {}

    if force_stage == 1:
        scores['stage1'] = stage1_fn()
        return scores, meta, 'stage1'

    if not skip_s1:
        scores['stage1'] = stage1_fn()

    if skip_s1 or scores.get('stage1', 0.0) < EARLY_EXIT_THRESHOLD:
        s2, m2 = stage2_fn()
        scores['stage2'] = s2
        meta['stage2'] = m2

    if scores.get('stage2', 0.0) < EARLY_EXIT_THRESHOLD:
        s3, m3 = stage3_fn()
        scores['stage3'] = s3
        meta['stage3'] = m3

    best_stage = max(scores, key=scores.get)
    return scores, meta, best_stage
