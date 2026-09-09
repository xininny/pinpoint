"""Metric computations: Top-K hit rate, MRR, ΔRank, ensemble."""
from __future__ import annotations

import statistics
from collections import defaultdict
from typing import Iterable, Optional


K_VALUES = (1, 3, 5, 10, 20)


def hit_at_k(rank: Optional[int], k: int) -> int:
    if rank is None:
        return 0
    return 1 if rank <= k else 0


def reciprocal_rank(rank: Optional[int]) -> float:
    if rank is None or rank <= 0:
        return 0.0
    return 1.0 / rank


def aggregate_ranks(ranks: list, ks: Iterable[int] = K_VALUES) -> dict:
    """Compute Top-K hit rate, MRR, median, no-hit rate from a list of (possibly None) ranks."""
    n = len(ranks)
    out = {'n': n}
    if n == 0:
        for k in ks:
            out[f'top{k}_hit'] = 0.0
        out['mrr'] = 0.0
        out['median_rank'] = None
        out['no_hit_rate'] = 0.0
        return out

    for k in ks:
        hits = sum(hit_at_k(r, k) for r in ranks)
        out[f'top{k}_hit'] = hits / n

    out['mrr'] = sum(reciprocal_rank(r) for r in ranks) / n

    valid = [r for r in ranks if r is not None]
    if valid:
        out['median_rank'] = statistics.median(valid)
    else:
        out['median_rank'] = None

    out['no_hit_rate'] = sum(1 for r in ranks if r is None) / n
    return out


def group_aggregate(records: list, group_keys: list, rank_field: str = 'rank_combined',
                    ks: Iterable[int] = K_VALUES) -> list:
    """records: list of dict. group_keys: list of dict keys. Returns rows of aggregated dicts."""
    buckets = defaultdict(list)
    for rec in records:
        key = tuple(rec.get(k, '') for k in group_keys)
        rk = rec.get(rank_field)
        buckets[key].append(rk)
    rows = []
    for key, ranks in buckets.items():
        row = {gk: kv for gk, kv in zip(group_keys, key)}
        agg = aggregate_ranks(ranks, ks)
        row.update(agg)
        rows.append(row)
    rows.sort(key=lambda r: tuple(r.get(gk, '') for gk in group_keys))
    return rows


def delta_rank_distribution(pairs: list) -> dict:
    """pairs: list of (rank_reg, rank_fno). Returns delta stats and category counts.

    delta = rank_reg - rank_fno (negative = fno better, positive = reg better)
    """
    deltas = []
    cat = {'fno_better': 0, 'tied': 0, 'reg_better': 0,
           'lost_only_fno': 0, 'lost_only_reg': 0, 'both_none': 0}
    for r_reg, r_fno in pairs:
        if r_reg is None and r_fno is None:
            cat['both_none'] += 1
        elif r_reg is None:
            cat['lost_only_reg'] += 1
        elif r_fno is None:
            cat['lost_only_fno'] += 1
        else:
            d = r_reg - r_fno
            deltas.append(d)
            if d > 0:
                cat['fno_better'] += 1
            elif d < 0:
                cat['reg_better'] += 1
            else:
                cat['tied'] += 1
    out = {
        'n_pairs': len(pairs),
        'n_both_ranked': len(deltas),
        'mean_delta': statistics.fmean(deltas) if deltas else 0.0,
        'median_delta': statistics.median(deltas) if deltas else 0.0,
        'stdev_delta': statistics.pstdev(deltas) if len(deltas) > 1 else 0.0,
    }
    out.update(cat)
    return out


def ensemble_rank(rank_a: Optional[int], rank_b: Optional[int]) -> Optional[int]:
    if rank_a is None:
        return rank_b
    if rank_b is None:
        return rank_a
    return min(rank_a, rank_b)
