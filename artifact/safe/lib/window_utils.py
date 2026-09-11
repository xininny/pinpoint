#!/usr/bin/env python3
"""
Shared sliding-window index math for Stage 2 (BB-level) / Stage 3
(token-level) reproduction on baselines that DO have a natural windowing
axis (trex, SAFE) -- mirrors
artifact/stage2_block_stride.py's
compute_window_start_range() and
artifact/backbone.py's make_sliding_windows(),
INCLUDING the tail-coverage-guarantee fix already applied to those files
(force the last reachable start index in, so target's final BB/token is
always covered by some window regardless of stride alignment).

These are pure index-math functions -- no model-specific embedding logic --
so both baselines can share one verified implementation instead of each
re-deriving the same off-by-one-prone logic.
"""


def compute_window_start_range(num_target_blocks: int, window_bb_count: int, stride: int) -> list:
    """BB-level (Stage 2) window start indices. See stage2_basicblock.py's
    compute_window_start_range() docstring for the full rule set."""
    if num_target_blocks == 1:
        return [0]

    full_max_start = num_target_blocks - window_bb_count
    if full_max_start >= 0:
        max_window_start = full_max_start
    else:
        min_window_bb_count = max(window_bb_count - 1, 1)
        max_window_start = num_target_blocks - min_window_bb_count
        if max_window_start < 0:
            return []

    starts = list(range(0, max_window_start + 1, stride))
    if starts[-1] != max_window_start:
        starts.append(max_window_start)
    return starts


def make_sliding_window_starts(n: int, window_size: int, stride: int) -> list:
    """Token-level (Stage 3) window start indices over a sequence of length n.
    Returns [0] with an implicit full-sequence window when n <= window_size."""
    if n <= window_size:
        return [0]
    last_start = n - window_size
    starts = list(range(0, last_start + 1, stride))
    if starts[-1] != last_start:
        starts.append(last_start)
    return starts
