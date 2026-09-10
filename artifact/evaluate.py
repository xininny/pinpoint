#!/usr/bin/env python3
"""
evaluate.py -- reproduce the paper's Table IV from a run's reports.

Within-function vulnerability range localization, over the reference queries
whose ground-truth target function came out at Top-1. A query counts as correct
when the range PinPoint reports overlaps the DWARF-derived vulnerable bytes at
all; covering the whole vulnerable region is not required.

Retrieval (Table III) is a separate measurement made by analysis/topk_table.py,
the paper's own code; see claims/claim1/.

Types follow the paper's taxonomy, read off the ground-truth label of the
instance: V -> Type I, NV-V -> Type II, V-NV -> Type III, V-V -> Type IV.

Types I and III reach 100% localization by construction: the vulnerable code
spans the whole target function, so any reported range inside it overlaps. The
informative rows are Types II and IV, where a vulnerable inlinee has to be
found inside a larger host.

Usage:
    python3 evaluate.py --results results/cascade
    python3 evaluate.py --results results/cascade --json out.json
"""
import argparse
import json
import os
import re
import sys
from collections import defaultdict

_ROOT = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_ROOT)

TYPE_OF_LABEL = {'V': 'Type I', 'NV-V': 'Type II', 'V-NV': 'Type III', 'V-V': 'Type IV'}
TYPE_ORDER = ['Type I', 'Type II', 'Type III', 'Type IV']

_QUERY = re.compile(r'^\[Query \d+/\d+\]\s*$')
_VFUNC = re.compile(r'^\s*Vuln func\s*:\s*(\S+)\s*$')
_VORIG = re.compile(r'^\s*Vuln origin\s*:\s*(\S+)\s+(\S+)-(\S+)\s*$')
_ROW = re.compile(r'^\s{4}(\d+)\.\s+(\S+)\s+(stage[123])\s+(\S+)\s+(\S+)\s+(\d+)\s*$')
_RANGE = re.compile(r'^\s*compared range\s*:\s*vuln=\[(\d+):(\d+)\]\s+target=\[(\d+):(\d+)\]\s*$')


def rel(p):
    try:
        return os.path.relpath(os.path.abspath(p), _REPO_ROOT)
    except ValueError:
        return p


def parse_report(path):
    """[{vuln_func, origin, rankings:[{rank,score,stage,func,label,tokens,range}]}]"""
    queries = []
    cur = None
    row = None
    with open(path) as f:
        for line in f:
            if _QUERY.match(line):
                cur = None
                row = None
                continue
            m = _VFUNC.match(line)
            if m:
                cur = {'vuln_func': m.group(1), 'origin': None, 'rankings': []}
                queries.append(cur)
                continue
            if cur is None:
                continue
            m = _VORIG.match(line)
            if m and cur['origin'] is None:
                cur['origin'] = f'{m.group(2)}-{m.group(3)}'
                continue
            m = _ROW.match(line)
            if m:
                row = {'rank': int(m.group(1)), 'score': float(m.group(2)),
                       'stage': m.group(3), 'func': m.group(4), 'label': m.group(5),
                       'tokens': int(m.group(6)), 'range': None}
                cur['rankings'].append(row)
                continue
            m = _RANGE.match(line)
            if m and row is not None:
                row['range'] = (int(m.group(3)), int(m.group(4)))
    return queries


def gt_candidates(entries, vuln_func):
    """Ground-truth target functions for this reference, per the paper's rule.

    A function qualifies either because it *is* the vulnerable function and still
    exists (labels V, V-V, V-NV), or because the compiler inlined the vulnerable
    function into it. Its ground-truth vulnerable bytes are the whole function in
    the first case and the inlined fragments in the second; a function can supply
    both, and then both are ground truth.
    """
    out = {}
    for e in entries:
        ranges = []
        if e['name'] == vuln_func and e['label'] in ('V', 'V-V', 'V-NV'):
            ranges.append((e['start'], e['end']))
        for inl in e.get('inlines', []):
            if inl['vuln_func'] == vuln_func:
                ranges.append((inl['start'], inl['end']))
        if ranges:
            out[e['name']] = {'label': e['label'], 'ranges': merge(ranges)}
    return out


def merge(iv):
    if not iv:
        return []
    out = []
    for lo, hi in sorted(iv):
        if out and lo <= out[-1][1]:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return [(a, b) for a, b in out]


def overlap_len(a, b):
    total = i = j = 0
    while i < len(a) and j < len(b):
        lo, hi = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        if hi > lo:
            total += hi - lo
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return total


# Basic-block addresses in the extracted JSON carry the loader base that the
# ground-truth address ranges do not; subtract it before comparing the two.
BB_ADDR_OFFSET = 0x100000


def block_offsets(fn):
    """Token offsets and ground-truth-space byte range for each basic block."""
    out = []
    cur = 0
    for bb in fn.get('basic_blocks') or []:
        n = len([t for t in (bb.get('norm_asm') or '').split(',') if t])
        out.append((cur, cur + n,
                    int(bb['start_addr_hex'], 16) - BB_ADDR_OFFSET,
                    int(bb['end_addr_hex'], 16) - BB_ADDR_OFFSET))
        cur += n
    return out


def tokens_to_bytes(blocks, lo, hi):
    """Byte ranges of the blocks the reported token window touches."""
    if hi <= lo:
        return []
    return merge([(s, e) for ts, te, s, e in blocks if ts < hi and te > lo])


def load_targets(data_dir, name):
    """Both reference databases are queried against the same default-build
    targets, so there is one target directory."""
    p = os.path.join(data_dir, 'targets', name + '.json')
    if not os.path.exists(p):
        return {}
    with open(p) as f:
        return {x['func_name']: x for x in json.load(f)}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--results', default=os.path.join(_ROOT, 'results', 'cascade'))
    ap.add_argument('--data', default=os.path.join(_ROOT, 'data'))
    ap.add_argument('--label', default=None, help='name for this configuration in the output')
    ap.add_argument('--json', help='also write the numbers as JSON here')
    args = ap.parse_args()

    with open(os.path.join(args.data, 'ground_truth', 'gt_ranges.json')) as f:
        GT = json.load(f)

    loc = defaultdict(lambda: {'queries': 0, 'correct': 0})
    seen_targets = set()
    tcache = {}

    for db in sorted(os.listdir(args.results)):
        db_dir = os.path.join(args.results, db)
        if not os.path.isdir(db_dir):
            continue
        for fn in sorted(os.listdir(db_dir)):
            if not (fn.startswith('result_') and fn.endswith('.txt')):
                continue
            build = fn[len('result_'):-len('.txt')]
            entries = GT.get(build)
            if not entries:
                continue
            seen_targets.add(build)
            # one build at a time: reports are walked in order, and a parsed
            # target file is large enough that holding 300 of them would not fit
            if tcache.get('key') != build:
                tcache.clear()
                tcache['key'] = build
                tcache['funcs'] = load_targets(args.data, build)
            funcs = tcache['funcs']

            for q in parse_report(os.path.join(db_dir, fn)):
                cands = gt_candidates(entries, q['vuln_func'])
                if not cands:
                    continue
                rows = {r['func']: r for r in q['rankings']}
                for name, info in cands.items():
                    typ = TYPE_OF_LABEL.get(info['label'])
                    if typ is None:
                        continue
                    # localization is scored only where this query put it at Top-1
                    r = rows.get(name)
                    if r is None or r['rank'] != 1 or r['range'] is None:
                        continue
                    tf = funcs.get(name)
                    if tf is None:
                        continue
                    pred = tokens_to_bytes(block_offsets(tf), r['range'][0], r['range'][1])
                    if not pred:
                        continue
                    loc[typ]['queries'] += 1
                    if overlap_len(pred, info['ranges']) > 0:
                        loc[typ]['correct'] += 1

    name = args.label or os.path.basename(args.results.rstrip('/'))
    print('TABLE IV: Within-function vulnerability range localization of')
    print('PinPoint-BinShot for reference queries whose ground-truth target appears at')
    print('Top-1. #Queries denotes the number of such reference queries. A query is')
    print('counted as Correct when at least one reported range overlaps the vulnerable')
    print('region; complete coverage of the region is not required. Accuracy is the')
    print('fraction of correct queries within each type.')
    print()
    print(f'  {"Type":<8}{"#Queries":>12}{"#Correct":>12}{"Accuracy":>12}')
    print('  ' + '-' * 44)
    lq = lc = 0
    for t in TYPE_ORDER:
        d = loc.get(t) or {'queries': 0, 'correct': 0}
        lq += d['queries']; lc += d['correct']
        acc = f'{100*d["correct"]/d["queries"]:.1f}%' if d['queries'] else '-'
        print(f'  {t.replace("Type ",""):<8}{d["queries"]:>12}{d["correct"]:>12}{acc:>12}')
    print('  ' + '-' * 44)
    tot = f'{100*lc/lq:.1f}%' if lq else '-'
    print(f'  {"Total":<8}{lq:>12}{lc:>12}{tot:>12}')

    if args.json:
        with open(args.json, 'w') as f:
            json.dump({'label': name, 'targets': len(seen_targets),
                       'localization': {t: dict(loc[t]) for t in loc}}, f, indent=1)
        print(f'\n  json    : {rel(args.json)}')
    return 0 if lq else 1


if __name__ == '__main__':
    sys.exit(main())
