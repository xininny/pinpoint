"""Ground truth predicates for vuln-query rankings."""
from __future__ import annotations

import re
from typing import Optional


V_LABELS = {'V', 'V-V', 'V-NV'}
INLINED_LABEL = 'NV-V'

# Compiler-generated suffix patterns (used by 5.add_flag.py normalize_func_name)
SUFFIX_DIGIT = re.compile(r'_(\d+)$')
SUFFIX_DOT_ANNOT = re.compile(r'\.(?:isra|constprop|part|cold|llvm)(?:\.\d+)?$')
SUFFIX_CLONE = re.compile(r'\.clone\.\d+$')
SUFFIX_DOT_DIGIT = re.compile(r'\.\d+$')


def normalize_func_name(name: str) -> str:
    n = (name or '').strip()
    n = SUFFIX_DIGIT.sub('', n)
    n = SUFFIX_DOT_ANNOT.sub('', n)
    n = SUFFIX_CLONE.sub('', n)
    n = SUFFIX_DOT_DIGIT.sub('', n)
    return n


def is_strict(rank_entry, query) -> bool:
    """Exact func_name match and target labeled as vulnerable."""
    return (
        rank_entry.func_name == query.vuln_func
        and rank_entry.label in V_LABELS
    )


def is_strict_with_clone(rank_entry, query) -> bool:
    """Strict OR clone-variant match (cpStripToTile vs cpStripToTile_0/_1)."""
    if is_strict(rank_entry, query):
        return True
    return (
        normalize_func_name(rank_entry.func_name) == query.vuln_func
        and rank_entry.label in V_LABELS
    )


def is_inlined(rank_entry, query) -> bool:
    """Target function is a caller that contains an inlined vuln."""
    return rank_entry.label == INLINED_LABEL


def is_combined(rank_entry, query) -> bool:
    return is_strict_with_clone(rank_entry, query) or is_inlined(rank_entry, query)


def best_rank(query, predicate) -> Optional[int]:
    """Return the smallest rank among ranking entries that satisfy predicate.

    None if no entry matches.
    """
    best = None
    for r in query.rankings:
        if predicate(r, query):
            if best is None or r.rank < best:
                best = r.rank
    return best


def best_rank_with_meta(query, predicate):
    """Like best_rank but also returns the matching entry."""
    best = None
    entry = None
    for r in query.rankings:
        if predicate(r, query):
            if best is None or r.rank < best:
                best = r.rank
                entry = r
    return best, entry
