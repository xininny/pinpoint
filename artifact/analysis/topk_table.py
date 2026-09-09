#!/usr/bin/env python3
"""Per-(project/binary/vuln_func/CVE/GT-location) Top-K rank table generator.

Query-based: groups by (project, binary_ver, vuln_func, CVE(s), GT-accepted
function name). CVE is included so two different vulnerabilities that happen
to share a vuln_func name aren't merged. GT-accepted function name is its own
group because GT sometimes lists >1 acceptable answer for one query (e.g. a
small vuln function inlined into several different callers — each caller is
a distinct real compiled function that now contains the vulnerable code, so
each is tracked and reported separately with its own rank, not folded into a
single best-of-N verdict). Section 5 (Coverage) re-aggregates by CVE only, to
show what fraction of a CVE's locations were found without letting a
heavily-inlined CVE outweigh a plain one in that specific view.

GT lookup key: (project, binary_ver, vuln_func, target_comp, db_type)
Valid test cases: (project, binary_ver, vuln_func) must appear in GT file.

EXCLUDE_PROJECTS is currently empty: DEFAULT_DB_DIR (old_2_sim_results) is a
complete, frozen snapshot for every project (verified 300/300 target files
per DB kind), so nothing needs excluding there. If you point --db-dir at a
run that's still in progress, set EXCLUDE_PROJECTS for the projects that
haven't finished yet — otherwise partial results get silently included.

Usage:
    python3 topk_table.py [--db-dir DIR] [--gt FILE] [--out FILE]
"""
from __future__ import annotations

import argparse
import bisect
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.parser import iter_txt_files, parse_file, RankingEntry

# ── Configuration ──────────────────────────────────────────────────────────────
# Vendored from the paper's analysis tree; paths resolve inside the artifact so
# the script runs wherever the repository is unpacked.
_ART_ROOT      = Path(__file__).resolve().parent.parent
DEFAULT_DB_DIR = _ART_ROOT / 'results' / 'cascade'
DEFAULT_GT     = _ART_ROOT / 'data' / 'ground_truth' / 'ground_truth_v3.txt'
DEFAULT_OUT    = _ART_ROOT / 'results' / 'topk_tables.txt'

EXCLUDE_PROJECTS = {}

DB_KINDS = ['regular', 'fno_inline']

DB_ORIGINS = [
    'clang-O0', 'clang-O1', 'clang-O2', 'clang-O3',
    'gcc-O0',   'gcc-O1',   'gcc-O2',   'gcc-O3',
]
TARGET_COMPS = [
    'clang-O1', 'clang-O2', 'clang-O3',
    'gcc-O1',   'gcc-O2',   'gcc-O3',
]

# Section 6: simulated target/vuln token-ratio pre-filter, applied BEFORE Stage 1
# (IQR-Tukey alpha for Type 1 (pure V) =
# 0.540, re-derived 2026-08-03 from ground_truth_v3, superseding the old 0.622).
PREFILTER_RATIO = 0.540

# ── Ground Truth parser ────────────────────────────────────────────────────────

_RE_TARGET   = re.compile(r'^#\s*TARGET 바이너리:\s*(\w+)/(\S+)')
_RE_CVE      = re.compile(r'^▼▼▼\s*(\S+)\s*▼▼▼')
_RE_FUNC     = re.compile(r'^──\s*Vuln func:\s*(\S+)')
_RE_COMP_OPT = re.compile(r'^\s{4}(clang|gcc)-(O\d)\s*$')
_RE_DB_LINE  = re.compile(r'^\s{8}(Regular|fno_inline)\s*\|.*\|\s*GT\s+(.*?)$')
_RE_GT_FUNC  = re.compile(r'\[(\w+)\]')


def _normalize_binary_ver(s: str) -> str:
    """'nm-new-20'→'nmnew-20', 'split-3'→'split-03', 'djpeg-6'→'djpeg-06'."""
    m = re.match(r'^(.*)-(\d+)$', s)
    if not m:
        return s
    return f'{m.group(1).replace("-", "")}-{m.group(2).zfill(2)}'


def load_gt(gt_path: Path) -> tuple[dict, set]:
    """Parse GT file.

    Returns:
        gt_lookup : (project, binary_ver, vuln_func, target_comp, db_type)
                    → list[gt_func_name]  (empty = unevaluable)
        gt_valid  : set of (project, binary_ver, vuln_func)
                    — used to filter out true-negative queries
    """
    gt_lookup: dict = {}
    gt_valid:  set  = set()

    project     = None
    binary_ver  = None
    vuln_func   = None
    target_comp = None

    with gt_path.open('r', encoding='utf-8') as f:
        for line in f:
            m = _RE_TARGET.match(line)
            if m:
                project     = m.group(1)
                binary_ver  = _normalize_binary_ver(m.group(2))
                vuln_func   = None
                target_comp = None
                continue

            if _RE_CVE.match(line):
                # CVE block start — reset func/comp but keep project/binary
                vuln_func   = None
                target_comp = None
                continue

            m = _RE_FUNC.match(line)
            if m:
                vuln_func   = m.group(1)
                target_comp = None
                if project and binary_ver:
                    gt_valid.add((project, binary_ver, vuln_func))
                continue

            m = _RE_COMP_OPT.match(line)
            if m:
                target_comp = f'{m.group(1)}-{m.group(2)}'
                continue

            m = _RE_DB_LINE.match(line)
            if m and project and binary_ver and vuln_func and target_comp:
                raw_db  = m.group(1)
                gt_part = m.group(2).strip()
                db_type = 'regular' if raw_db == 'Regular' else 'fno_inline'

                if '정답 없음' in gt_part or 'info 없음' in gt_part or not gt_part:
                    gt_funcs = []
                else:
                    gt_funcs = _RE_GT_FUNC.findall(gt_part)

                key = (project, binary_ver, vuln_func, target_comp, db_type)
                # Merge if seen before (same func in multiple CVE blocks)
                existing = gt_lookup.get(key, [])
                merged   = list(dict.fromkeys(existing + gt_funcs))
                gt_lookup[key] = merged

    return gt_lookup, gt_valid


# ── File / query helpers ───────────────────────────────────────────────────────

def binary_version(q) -> str:
    base  = q.target_file.replace('.json', '')
    parts = base.split('-')
    return '-'.join(parts[1:-2])


def find_all(rankings, gt_funcs: list) -> list:
    """Return [(name, rank_or_None, score_or_None, label_or_None), ...] for EVERY
    name in gt_funcs.

    gt_funcs can legitimately contain >1 name — e.g. a small vuln function that
    got inlined into several different callers means each caller is its own
    real, distinct compiled function that now physically contains the
    vulnerable code. Each one is tracked and reported as its own test case
    (see the main loop) rather than collapsed into a single best-of-N verdict,
    so you can see exactly which of the N locations were found and which
    weren't.

    label is the candidate's own V/NV-V/V-NV/V-V/NV/NV-NV tag as printed on its
    ranking row (see RANK_ROW in lib/parser.py) — i.e. whether the GT-accepted
    function is itself the vuln func (V/V-NV/V-V) or a caller that absorbed an
    inlined vuln func (NV-V). Used by section 8 (Top-K by GT-answer type).
    """
    by_name = {r.func_name: (r.rank, r.score, r.label) for r in rankings}
    return [(name,) + by_name.get(name, (None, None, None)) for name in gt_funcs]


def apply_token_prefilter(rankings, vuln_tokens: int, ratio_threshold: float) -> list:
    """Simulate a target/vuln token-ratio filter applied BEFORE Stage 1 even runs:
    drop every candidate whose (target tokens / vuln tokens) is below threshold,
    then re-rank the survivors. Dropping candidates doesn't change the relative
    score order among the ones that remain, so a survivor's new rank is
    1 + (# surviving candidates with a strictly better original rank) —
    standard competition ranking, so ties (e.g. many candidates tied at rank 1
    after heavy inlining collapses several functions to an identical score)
    stay tied instead of being arbitrarily split apart by list order. If the
    GT-correct candidate itself falls below the ratio, it's gone too —
    find_all() will report it as not-found (None), same as any other no-hit.
    """
    if vuln_tokens <= 0:
        return list(rankings)
    survivors = [r for r in rankings if r.tokens / vuln_tokens >= ratio_threshold]
    sorted_ranks = sorted(r.rank for r in survivors)
    return [
        RankingEntry(rank=bisect.bisect_left(sorted_ranks, r.rank) + 1,
                     score=r.score, best_stage=r.best_stage,
                     func_name=r.func_name, label=r.label, tokens=r.tokens)
        for r in survivors
    ]


def cell_str(rank, score, func=None, query=None) -> str:
    return 'N/A' if rank is None else f'{rank} ({score:.2f})'


# ── Top-K computation ──────────────────────────────────────────────────────────

K_VALUES = (1, 3, 5, 10)

# Section 8: GT-answer's own inlining type, per RANK_ROW's label tag
# (V/NV-V/V-NV/V-V/NV/NV-NV — see lib/parser.py). A GT-accepted function
# should always be one of these four (it must contain vuln code somewhere):
#   Type I   V     — self IS the vuln func, no inlining noise
#   Type II  NV-V  — self is NOT the vuln func, but a vuln func got inlined
#                    into it (this caller is the GT-accepted answer)
#   Type III V-NV  — self IS the vuln func, and some non-vuln code got
#                    inlined into it too
#   Type IV  V-V   — self IS the vuln func, and ANOTHER vuln func got
#                    inlined into it as well
TYPE_LABELS = [
    ('V',    'Type I  (V)'),
    ('NV-V', 'Type II (NV-V)'),
    ('V-NV', 'Type III(V-NV)'),
    ('V-V',  'Type IV (V-V)'),
]


def topk_stats(ranks: list) -> dict:
    n = len(ranks)
    if n == 0:
        return {f'Top-{k}': 0.0 for k in K_VALUES} | {'MRR': 0.0, 'no_hit': 0.0, 'n': 0}
    hits  = {k: sum(1 for r in ranks if r is not None and r <= k) for k in K_VALUES}
    valid = [r for r in ranks if r is not None]
    mrr   = sum(1.0 / r for r in valid) / n
    return {
        **{f'Top-{k}': hits[k] / n for k in K_VALUES},
        'MRR':    mrr,
        'no_hit': sum(1 for r in ranks if r is None) / n,
        'n':      n,
    }


def coverage_stats(cov_list: list) -> dict:
    """cov_list: list of per-CVE-test location-rank lists (one entry per test case,
    each entry itself a list of rank-or-None — one per GT-accepted location for
    that test). Returns AVERAGE coverage@K across test cases.

    Each test case (= one CVE at one target/origin/db cell) is weighted equally
    regardless of how many GT-accepted locations it has (1 for a plain function,
    N for one with N inlined/cloned copies) — a CVE with many copies doesn't get
    extra votes here, same fairness goal as topk_stats. What differs is *within*
    one test case: instead of "did we find ANY location" (find_rank), this asks
    "what FRACTION of the N locations did we find within Top-K".
    """
    n = len(cov_list)
    if n == 0:
        return {f'Cov-{k}': 0.0 for k in K_VALUES} | {'avg_locs': 0.0, 'n': 0}
    per_k_fracs = {k: [] for k in K_VALUES}
    total_locations = 0
    for ranks in cov_list:
        total_locations += len(ranks)
        if not ranks:
            continue
        for k in K_VALUES:
            found = sum(1 for r in ranks if r is not None and r <= k)
            per_k_fracs[k].append(found / len(ranks))
    return {
        **{f'Cov-{k}': (sum(per_k_fracs[k]) / n) for k in K_VALUES},
        'avg_locs': total_locations / n,
        'n': n,
    }


def fmt_pct(v: float) -> str:
    return f'{v * 100:.1f}%'


def fmt_summary_table(groups: list) -> str:
    COL_W   = [28, 6, 7, 7, 7, 7, 6, 7]
    headers = ['Group', 'n', 'Top-1', 'Top-3', 'Top-5', 'Top-10', 'MRR', 'No-hit']
    sep     = '-' * (sum(COL_W) + 2 * len(COL_W))

    def fmt_row(label, s):
        vals = [
            label, str(s['n']),
            fmt_pct(s['Top-1']), fmt_pct(s['Top-3']),
            fmt_pct(s['Top-5']), fmt_pct(s['Top-10']),
            f"{s['MRR']:.3f}", fmt_pct(s['no_hit']),
        ]
        return '  '.join(v.ljust(COL_W[i]) for i, v in enumerate(vals))

    hdr   = '  '.join(h.ljust(COL_W[i]) for i, h in enumerate(headers))
    lines = [sep, hdr, sep]
    for label, s in groups:
        lines.append(fmt_row(label, s))
    lines.append(sep)
    return '\n'.join(lines)


def fmt_coverage_table(groups: list) -> str:
    COL_W   = [28, 6, 9, 7, 7, 7, 7]
    headers = ['Group', 'n', 'avg_locs', 'Cov-1', 'Cov-3', 'Cov-5', 'Cov-10']
    sep     = '-' * (sum(COL_W) + 2 * len(COL_W))

    def fmt_row(label, s):
        vals = [
            label, str(s['n']), f"{s['avg_locs']:.2f}",
            fmt_pct(s['Cov-1']), fmt_pct(s['Cov-3']),
            fmt_pct(s['Cov-5']), fmt_pct(s['Cov-10']),
        ]
        return '  '.join(v.ljust(COL_W[i]) for i, v in enumerate(vals))

    hdr   = '  '.join(h.ljust(COL_W[i]) for i, h in enumerate(headers))
    lines = [sep, hdr, sep]
    for label, s in groups:
        lines.append(fmt_row(label, s))
    lines.append(sep)
    return '\n'.join(lines)


def fmt_type_table(groups: list) -> str:
    COL_W   = [18, 6, 7, 7, 7, 7]
    headers = ['Group', 'n', 'Top-1', 'Top-5', 'Top-10', 'MRR']
    sep     = '-' * (sum(COL_W) + 2 * len(COL_W))

    def fmt_row(label, s):
        vals = [
            label, str(s['n']),
            fmt_pct(s['Top-1']), fmt_pct(s['Top-5']), fmt_pct(s['Top-10']),
            f"{s['MRR']:.3f}",
        ]
        return '  '.join(v.ljust(COL_W[i]) for i, v in enumerate(vals))

    hdr   = '  '.join(h.ljust(COL_W[i]) for i, h in enumerate(headers))
    lines = [sep, hdr, sep]
    for label, s in groups:
        lines.append(fmt_row(label, s))
    lines.append(sep)
    return '\n'.join(lines)


def fmt_merged_table(rows: list) -> str:
    """Merged table without DB column (one row per target_comp)."""
    TW = 10
    n = len(DB_ORIGINS)
    col_w = [len(h) for h in DB_ORIGINS]
    for row in rows:
        for i in range(n):
            col_w[i] = max(col_w[i], len(str(row[1 + i])))
    pad = 2
    hdr = 'target'.ljust(TW) + (' ' * pad).join(
        DB_ORIGINS[i].rjust(col_w[i]) for i in range(n)
    )
    sep = '-' * len(hdr)
    lines = [sep, hdr, sep]
    for row in rows:
        cells = (' ' * pad).join(str(row[1 + i]).rjust(col_w[i]) for i in range(n))
        lines.append(row[0].ljust(TW) + cells)
    lines.append(sep)
    return '\n'.join(lines)


def fmt_table(rows: list) -> str:
    TW, DBW = 10, 12
    n = len(DB_ORIGINS)
    col_w = [len(h) for h in DB_ORIGINS]
    for row in rows:
        for i in range(n):
            col_w[i] = max(col_w[i], len(str(row[2 + i])))
    pad = 2
    hdr = 'target'.ljust(TW) + 'DB'.ljust(DBW) + (' ' * pad).join(
        DB_ORIGINS[i].rjust(col_w[i]) for i in range(n)
    )
    sep = '-' * len(hdr)
    lines = [sep, hdr, sep]
    for row in rows:
        cells = (' ' * pad).join(str(row[2 + i]).rjust(col_w[i]) for i in range(n))
        lines.append(row[0].ljust(TW) + row[1].ljust(DBW) + cells)
    lines.append(sep)
    return '\n'.join(lines)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--db-dir',  default=str(DEFAULT_DB_DIR))
    ap.add_argument('--gt',      default=str(DEFAULT_GT))
    ap.add_argument('--out',     default=str(DEFAULT_OUT))
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()

    db_root  = Path(args.db_dir)
    gt_path  = Path(args.gt)
    out_path = Path(args.out)

    # 1. Load GT ──────────────────────────────────────────────────────────────
    print('[1/4] Loading ground truth...', file=sys.stderr)
    gt_lookup, gt_valid = load_gt(gt_path)
    print(f'  {len(gt_lookup)} GT entries, '
          f'{len(gt_valid)} valid (project/binary/func) groups', file=sys.stderr)

    # 2. Parse result files ───────────────────────────────────────────────────
    print('[2/4] Parsing TXT result files...', file=sys.stderr)
    all_queries = []
    warnings    = []

    for db_kind in DB_KINDS:
        db_dir = db_root / db_kind
        if not db_dir.is_dir():
            continue
        n = 0
        for path in iter_txt_files(db_dir):
            queries, _ = parse_file(path, db_kind=db_kind,
                                    warn_cb=warnings.append)
            for q in queries:
                if q.target_project not in EXCLUDE_PROJECTS:
                    all_queries.append(q)
            n += 1
        kept = sum(1 for q in all_queries if q.db_kind == db_kind)
        print(f'  {db_kind}: {n} files → {kept} queries kept', file=sys.stderr)
    print(f'  Total: {len(all_queries)} queries', file=sys.stderr)

    # 3. Group and compute ranks ──────────────────────────────────────────────
    print('[3/4] Grouping and computing GT-based ranks...', file=sys.stderr)

    # lookup[gkey][(db, tc, orig)] = (rank, score, matched_func)
    # gkey = (project, binary_ver, vuln_func, CVE tuple, GT-accepted func name) —
    # every GT-accepted location is its OWN group. If a small vuln function got
    # inlined into 15 different callers, that's 15 separate real compiled
    # functions each now containing the vulnerable code, so each gets its own
    # row/rank here rather than being folded into a single best-of-15 verdict.
    lookup:   dict = defaultdict(dict)
    # coverage[cvekey][(db, tc, orig)] = [rank_or_None, ...] one entry per
    # GT-accepted location for that cell, grouped by CVE only (not by
    # individual location) — used for the section-5 "coverage" view: of the
    # N locations this CVE has here, what fraction did we find. One sample
    # per CVE-test, regardless of N, so a heavily-inlined CVE doesn't get N
    # times the weight of a plain one in that specific aggregate.
    coverage: dict = defaultdict(dict)
    # lookup_filtered: same gkey scheme as `lookup`, but built from rankings that
    # went through apply_token_prefilter() first — simulates the token-ratio
    # filter running before Stage 1 instead of not at all. See section 6.
    lookup_filtered: dict = defaultdict(dict)
    # GT-location drop rate under the pre-filter, independent of rank/Top-K:
    # of the GT-accepted locations that actually show up as a candidate at all
    # (orig rank is not None), what fraction have their own token ratio below
    # the threshold and so get discarded by the filter outright (see section 7).
    gt_drop_total:    dict = defaultdict(int)
    gt_drop_filtered: dict = defaultdict(int)
    n_skip_gt = 0       # queries with no GT entry
    n_no_gt   = 0       # queries where GT says unevaluable

    for q in all_queries:
        bv       = binary_version(q)
        base_key = (q.target_project, bv, q.vuln_func)

        # Skip true-negatives: (project, bv, func) not in GT file at all
        if base_key not in gt_valid:
            n_skip_gt += 1
            continue

        db    = q.db_kind
        tc    = f'{q.target_compiler}-{q.target_opt}'
        orig  = f'{q.vuln_compiler}-{q.vuln_opt}'

        # GT function lookup — target is always regular-compiled, regardless of DB kind
        gt_key   = (q.target_project, bv, q.vuln_func, tc, 'regular')
        gt_funcs = gt_lookup.get(gt_key, [])

        if not gt_funcs:
            # GT says unevaluable (DB missing, GT ❌, or (info 없음))
            n_no_gt += 1
            continue

        located   = find_all(q.rankings, gt_funcs)  # [(name, rank, score, label), ...]
        cve_tuple = tuple(sorted(q.vuln_cves))
        cell_key  = (db, tc, orig)

        # gkey includes the CVE(s) so that two DIFFERENT vulnerabilities that
        # happen to share a vuln_func name (e.g. binutils/decode_line_info is
        # vulnerable under both CVE-2017-15025 and CVE-2017-14939) are kept as
        # separate test cases instead of silently collapsing into whichever
        # one ranks better. A single vuln DB row that's tagged with multiple
        # CVE numbers (e.g. one commit fixing 3 CVEs at once) is still ONE
        # real comparison, so cve_tuple bundles those together on purpose.
        for name, rk, sc, lbl in located:
            gkey = (q.target_project, bv, q.vuln_func, cve_tuple, name)
            prev = lookup[gkey].get(cell_key)
            if prev is None or (rk is not None and (prev[0] is None or rk < prev[0])):
                lookup[gkey][cell_key] = (rk, sc, name, lbl)

        cvekey = (q.target_project, bv, q.vuln_func, cve_tuple)
        if cell_key not in coverage[cvekey]:
            coverage[cvekey][cell_key] = [rk for _, rk, _, _ in located]

        filtered_rankings = apply_token_prefilter(q.rankings, q.vuln_tokens, PREFILTER_RATIO)
        located_f = find_all(filtered_rankings, gt_funcs)
        for name, rk, sc, lbl in located_f:
            gkey = (q.target_project, bv, q.vuln_func, cve_tuple, name)
            prev = lookup_filtered[gkey].get(cell_key)
            if prev is None or (rk is not None and (prev[0] is None or rk < prev[0])):
                lookup_filtered[gkey][cell_key] = (rk, sc, name, lbl)

        # located/located_f share the same gt_funcs order, so zip them directly
        for (name, rk, _sc, _lbl), (_name2, rk_f, _sc2, _lbl2) in zip(located, located_f):
            if rk is not None:
                gt_drop_total[db] += 1
                if rk_f is None:
                    gt_drop_filtered[db] += 1

    n_groups = len(lookup)
    print(f'  {n_groups} groups  |  '
          f'{n_skip_gt} queries skipped (not in GT)  |  '
          f'{n_no_gt} unevaluable (GT empty)', file=sys.stderr)

    # 4. Build output ─────────────────────────────────────────────────────────
    print('[4/4] Writing tables...', file=sys.stderr)

    out_lines:       list[str]  = []
    agg_points:      list[dict] = []
    coverage_points: list[dict] = []

    for gkey in sorted(lookup):
        project, bv_str, vuln_func, cve_tuple, gt_func = gkey
        cells = lookup[gkey]

        out_lines.append('=' * 80)
        out_lines.append(f'Project : {project}/{bv_str}')
        out_lines.append(f'Query   : {vuln_func}')
        out_lines.append(f'CVE     : {", ".join(cve_tuple) if cve_tuple else "(none)"}')
        out_lines.append(f'GT func : {gt_func}')

        # Show which target_comps have this specific gt_func in their GT
        tc_with_gt = [tc for tc in TARGET_COMPS
                      if gt_func in gt_lookup.get((project, bv_str, vuln_func, tc, 'regular'), [])]
        out_lines.append(f'GT target: {", ".join(tc_with_gt)}')
        out_lines.append('')

        rows = []
        for tc in TARGET_COMPS:
            for j, db in enumerate(DB_KINDS):
                row = [tc if j == 0 else '', db]
                for orig in DB_ORIGINS:
                    rk, sc, fn, lbl = cells.get((db, tc, orig), (None, None, None, None))
                    row.append(cell_str(rk, sc, fn, vuln_func))

                    if (db, tc, orig) in cells:
                        agg_points.append({
                            'db':            db,
                            'rank':          rk,
                            'same_compiler': tc.split('-')[0] == orig.split('-')[0],
                            'origin_opt':    orig.split('-')[1],
                            'project':       project,
                            'label':         lbl,
                        })
                rows.append(row)

        out_lines.append(fmt_table(rows))
        out_lines.append('')

        # ── Merged tables (regular + fno_inline combined) ────────────────────
        merged_rank_rows  = []
        merged_score_rows = []
        for tc in TARGET_COMPS:
            rank_row  = [tc]
            score_row = [tc]
            for orig in DB_ORIGINS:
                reg = cells.get(('regular',    tc, orig), (None, None, None, None))
                fno = cells.get(('fno_inline', tc, orig), (None, None, None, None))
                rk_r, sc_r, _, lbl_r = reg
                rk_f, sc_f, _, lbl_f = fno

                # best by rank (lower = better)
                if rk_r is None and rk_f is None:
                    best_rk, best_rk_label = (None, None), None
                elif rk_r is None:
                    best_rk, best_rk_label = (rk_f, sc_f), lbl_f
                elif rk_f is None:
                    best_rk, best_rk_label = (rk_r, sc_r), lbl_r
                elif rk_r <= rk_f:
                    best_rk, best_rk_label = (rk_r, sc_r), lbl_r
                else:
                    best_rk, best_rk_label = (rk_f, sc_f), lbl_f

                # best by score (higher = better)
                if sc_r is None and sc_f is None:
                    best_sc, best_sc_label = (None, None), None
                elif sc_r is None:
                    best_sc, best_sc_label = (rk_f, sc_f), lbl_f
                elif sc_f is None:
                    best_sc, best_sc_label = (rk_r, sc_r), lbl_r
                elif sc_r >= sc_f:
                    best_sc, best_sc_label = (rk_r, sc_r), lbl_r
                else:
                    best_sc, best_sc_label = (rk_f, sc_f), lbl_f

                rank_row.append(cell_str(*best_rk))
                score_row.append(cell_str(*best_sc))

                has_any = (('regular', tc, orig) in cells or
                           ('fno_inline', tc, orig) in cells)
                if has_any:
                    sc_flag = tc.split('-')[0] == orig.split('-')[0]
                    opt     = orig.split('-')[1]
                    agg_points.append({
                        'db': 'merged_rank',  'rank': best_rk[0],
                        'same_compiler': sc_flag, 'origin_opt': opt,
                        'project': project, 'label': best_rk_label,
                    })
                    agg_points.append({
                        'db': 'merged_score', 'rank': best_sc[0],
                        'same_compiler': sc_flag, 'origin_opt': opt,
                        'project': project, 'label': best_sc_label,
                    })

            merged_rank_rows.append(rank_row)
            merged_score_rows.append(score_row)

        out_lines.append('MERGED (best rank):')
        out_lines.append(fmt_merged_table(merged_rank_rows))
        out_lines.append('')
        out_lines.append('MERGED (best score):')
        out_lines.append(fmt_merged_table(merged_score_rows))
        out_lines.append('')

    # coverage_points: built from `coverage` directly (grouped by CVE only, NOT
    # by individual location) — one sample per CVE-test, unlike agg_points
    # above which now has one sample per individual location.
    for cvekey, cells in coverage.items():
        project = cvekey[0]
        for (db, tc, orig), ranks in cells.items():
            coverage_points.append({
                'db':            db,
                'ranks':         ranks,
                'same_compiler': tc.split('-')[0] == orig.split('-')[0],
                'origin_opt':    orig.split('-')[1],
                'project':       project,
            })

    # ── Final Top-K summary ──────────────────────────────────────────────────
    out_lines += [
        '=' * 80,
        'FINAL TOP-K SUMMARY',
        '=' * 80,
        '',
        'Each cell = one test case: (vuln_func, CVE, GT-accepted location, DB_origin, target_comp).',
        'Each GT-accepted location (e.g. one of several inlined-into callers) is its own row —',
        'see section 5 for a CVE-level (not per-location) view.',
        '"N/A" = no DB entry, GT unevaluable, or true-negative (not in GT file).',
        '',
    ]

    # 1. Overall by DB type
    out_lines.append('1. Overall Top-K  (by DB type)')
    out_lines.append('')
    overall = [(db, topk_stats([p['rank'] for p in agg_points if p['db'] == db]))
               for db in DB_KINDS + ['merged_rank', 'merged_score']]
    out_lines.append(fmt_summary_table(overall))
    out_lines.append('')

    # 2. same vs cross compiler
    out_lines.append('2. Top-K by same-compiler vs cross-compiler')
    out_lines.append('')
    sc_rows = []
    for db in DB_KINDS:
        for same in (True, False):
            label = f'{db}  {"same" if same else "cross"}-compiler'
            ranks = [p['rank'] for p in agg_points
                     if p['db'] == db and p['same_compiler'] == same]
            sc_rows.append((label, topk_stats(ranks)))
    out_lines.append(fmt_summary_table(sc_rows))
    out_lines.append('')

    # 3. By DB origin opt level
    out_lines.append('3. Top-K by DB origin optimization level')
    out_lines.append('')
    opt_rows = []
    for db in DB_KINDS:
        for opt in ('O0', 'O1', 'O2', 'O3'):
            ranks = [p['rank'] for p in agg_points
                     if p['db'] == db and p['origin_opt'] == opt]
            if ranks:
                opt_rows.append((f'{db}  origin={opt}', topk_stats(ranks)))
    out_lines.append(fmt_summary_table(opt_rows))
    out_lines.append('')

    # 4. Per project
    out_lines.append('4. Top-K per project')
    out_lines.append('')
    proj_ranks: dict = defaultdict(list)
    for p in agg_points:
        proj_ranks[p['project']].append(p['rank'])
    out_lines.append(fmt_summary_table(
        [(proj, topk_stats(ranks)) for proj, ranks in sorted(proj_ranks.items())]
    ))
    out_lines.append('')

    # 5. Coverage — how much of a multi-location CVE (inlined/cloned into several
    # target functions) does the detector actually surface, not just "found ≥1"
    out_lines.append('5. Coverage  (of GT-accepted locations found within Top-K, per CVE-test)')
    out_lines.append('   avg_locs = average # of GT-accepted answer names per CVE-test')
    out_lines.append('   (e.g. when a small vuln function gets inlined into several callers,')
    out_lines.append('    every caller is a valid "found it" location — avg_locs > 1 means')
    out_lines.append('    that happens often in this DB). Cov-K = avg fraction of those')
    out_lines.append('    locations ranked ≤ K, one CVE-test = one equally-weighted sample')
    out_lines.append('    (a CVE with 16 locations does not get 16x the weight of one with 1).')
    out_lines.append('')
    cov_overall = [(db, coverage_stats([p['ranks'] for p in coverage_points if p['db'] == db]))
                   for db in DB_KINDS]
    out_lines.append(fmt_coverage_table(cov_overall))
    out_lines.append('')

    # 6. Section-1-equivalent, but with a token-ratio pre-filter applied before
    # Stage 1 (see apply_token_prefilter / PREFILTER_RATIO above).
    agg_points_filtered: list[dict] = []
    for gkey, cells in lookup_filtered.items():
        project = gkey[0]
        for tc in TARGET_COMPS:
            for orig in DB_ORIGINS:
                reg = cells.get(('regular', tc, orig))
                fno = cells.get(('fno_inline', tc, orig))
                for db, entry in (('regular', reg), ('fno_inline', fno)):
                    if entry is not None:
                        rk, sc, fn, lbl = entry
                        agg_points_filtered.append({
                            'db': db, 'rank': rk,
                            'same_compiler': tc.split('-')[0] == orig.split('-')[0],
                            'origin_opt':    orig.split('-')[1],
                            'project':       project, 'label': lbl,
                        })
                if reg is None and fno is None:
                    continue
                rk_r, sc_r, _, lbl_r = reg if reg else (None, None, None, None)
                rk_f, sc_f, _, lbl_f = fno if fno else (None, None, None, None)

                if rk_r is None and rk_f is None:
                    best_rk, best_rk_label = None, None
                elif rk_r is None:
                    best_rk, best_rk_label = rk_f, lbl_f
                elif rk_f is None:
                    best_rk, best_rk_label = rk_r, lbl_r
                elif rk_r <= rk_f:
                    best_rk, best_rk_label = rk_r, lbl_r
                else:
                    best_rk, best_rk_label = rk_f, lbl_f

                if sc_r is None and sc_f is None:
                    best_sc_rank, best_sc_label = None, None
                elif sc_r is None:
                    best_sc_rank, best_sc_label = rk_f, lbl_f
                elif sc_f is None:
                    best_sc_rank, best_sc_label = rk_r, lbl_r
                elif sc_r >= sc_f:
                    best_sc_rank, best_sc_label = rk_r, lbl_r
                else:
                    best_sc_rank, best_sc_label = rk_f, lbl_f

                sc_flag = tc.split('-')[0] == orig.split('-')[0]
                opt     = orig.split('-')[1]
                agg_points_filtered.append({
                    'db': 'merged_rank', 'rank': best_rk,
                    'same_compiler': sc_flag, 'origin_opt': opt, 'project': project,
                    'label': best_rk_label,
                })
                agg_points_filtered.append({
                    'db': 'merged_score', 'rank': best_sc_rank,
                    'same_compiler': sc_flag, 'origin_opt': opt, 'project': project,
                    'label': best_sc_label,
                })

    out_lines.append(
        f'6. Overall Top-K WITH token-ratio pre-filter '
        f'(target/vuln tokens >= {PREFILTER_RATIO}, applied before Stage 1)'
    )
    out_lines.append('   Simulates dropping every candidate target function whose token count is')
    out_lines.append(f'   below {PREFILTER_RATIO * 100:.1f}% of the vuln function\'s token count, BEFORE any')
    out_lines.append('   stage runs. Survivors keep their original score order; ranks are recomputed')
    out_lines.append('   among survivors only. If the GT-correct location itself falls below the ratio,')
    out_lines.append('   it is dropped too and counts as a no-hit for that test case.')
    out_lines.append('')
    overall_filtered = [
        (db, topk_stats([p['rank'] for p in agg_points_filtered if p['db'] == db]))
        for db in DB_KINDS + ['merged_rank', 'merged_score']
    ]
    out_lines.append(fmt_summary_table(overall_filtered))
    out_lines.append('')

    # 7. GT-location drop rate under the pre-filter — NOT a Top-K/rank metric.
    # Of the GT-accepted locations that show up as a candidate at all, what
    # fraction get discarded outright because their own token ratio is below
    # threshold (i.e. the correct answer itself would never even reach
    # Stage 1). Same statistic style as the "GT filtered: X/Y" annotation on
    # the box-plot this threshold came from, but computed over this dataset.
    out_lines.append(
        f'7. GT-location drop rate under the pre-filter (ratio < {PREFILTER_RATIO}), independent of Top-K'
    )
    out_lines.append('   Of the GT-accepted locations that appear as a candidate at all, the fraction')
    out_lines.append('   whose OWN token ratio falls below the threshold — i.e. the correct answer')
    out_lines.append('   itself would be discarded before Stage 1 ever runs, regardless of rank.')
    out_lines.append('')
    COL_W = [28, 10, 10, 10]
    headers = ['Group', 'dropped', 'total', 'drop %']
    sep = '-' * (sum(COL_W) + 2 * len(COL_W))
    gt_drop_lines = [sep, '  '.join(h.ljust(COL_W[i]) for i, h in enumerate(headers)), sep]
    total_dropped = sum(gt_drop_filtered.values())
    total_all     = sum(gt_drop_total.values())
    for db in DB_KINDS:
        d, t = gt_drop_filtered[db], gt_drop_total[db]
        pct  = f'{(d / t * 100):.1f}%' if t else 'N/A'
        gt_drop_lines.append('  '.join(v.ljust(COL_W[i]) for i, v in enumerate(
            [db, str(d), str(t), pct]
        )))
    overall_pct = f'{(total_dropped / total_all * 100):.1f}%' if total_all else 'N/A'
    gt_drop_lines.append('  '.join(v.ljust(COL_W[i]) for i, v in enumerate(
        ['overall', str(total_dropped), str(total_all), overall_pct]
    )))
    gt_drop_lines.append(sep)
    out_lines.append('\n'.join(gt_drop_lines))
    out_lines.append('')

    # 8/9. Top-K by GT-answer inlining Type, split by the GT-accepted
    # function's OWN label instead of by db type. label comes straight off
    # that function's ranking row (see find_all()), so it reflects the target
    # binary's actual compiled form, independent of which vuln query produced
    # the match. Shown per db kind (regular / fno_inline, i.e. NOT merged —
    # each alone, no best-of-both-picked) plus merged (best rank), same three
    # groupings as section 1.
    def type_rows_for(points: list, db: str) -> list:
        pts = [p for p in points if p['db'] == db]
        rows = [
            (disp, topk_stats([p['rank'] for p in pts if p.get('label') == code]))
            for code, disp in TYPE_LABELS
        ]
        rows.append(('Total', topk_stats([p['rank'] for p in pts])))
        return rows

    TYPE_DB_GROUPS = [
        ('regular',     'regular    (fno_inline NOT merged in)'),
        ('fno_inline',  'fno_inline (regular NOT merged in)'),
        ('merged_rank', 'merged (best rank of regular+fno_inline)'),
    ]

    out_lines.append('8. Top-K by GT-answer inlining Type')
    out_lines.append('   Type I  = V     : self is the vuln func, clean (no inlining involvement)')
    out_lines.append('   Type II = NV-V  : self is NOT the vuln func, but a vuln func got inlined into it')
    out_lines.append('   Type III= V-NV  : self IS the vuln func, with non-vuln code also inlined in')
    out_lines.append('   Type IV = V-V   : self IS the vuln func, with ANOTHER vuln func also inlined in')
    out_lines.append('   "Total" = all test cases for that db grouping, including any GT answer whose')
    out_lines.append('   label could not be resolved (e.g. genuinely absent from that target ranking) —')
    out_lines.append('   Type I..IV counts may not sum to Total n for that reason.')
    out_lines.append('')
    for db_key, db_disp in TYPE_DB_GROUPS:
        out_lines.append(f'  db = {db_disp}')
        out_lines.append(fmt_type_table(type_rows_for(agg_points, db_key)))
        out_lines.append('')

    # 9. Section-8-equivalent, but WITH the token-ratio pre-filter (section 6)
    # applied first — same relationship section 6 has to section 1.
    out_lines.append(
        f'9. Top-K by GT-answer inlining Type WITH token-ratio pre-filter '
        f'(target/vuln tokens >= {PREFILTER_RATIO})'
    )
    out_lines.append('   Same Type definitions and db groupings as section 8, but computed over the')
    out_lines.append('   same pre-filtered population as section 6 (candidates below the ratio dropped')
    out_lines.append('   before Stage 1, ranks recomputed among survivors). A GT answer whose own')
    out_lines.append('   token ratio falls below the threshold is dropped too (counts as no-hit),')
    out_lines.append('   same caveat as section 6/7.')
    out_lines.append('')
    for db_key, db_disp in TYPE_DB_GROUPS:
        out_lines.append(f'  db = {db_disp}')
        out_lines.append(fmt_type_table(type_rows_for(agg_points_filtered, db_key)))
        out_lines.append('')

    out_lines.append('=' * 80)
    out_lines.append(
        f'Total tables: {n_groups}  |  Total test cases: {len(agg_points)}'
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        f.write('\n'.join(out_lines) + '\n')

    print(f'\nWrote {n_groups} tables → {out_path}', file=sys.stderr)


if __name__ == '__main__':
    main()
