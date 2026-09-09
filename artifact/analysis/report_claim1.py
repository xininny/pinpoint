#!/usr/bin/env python3
"""
report_claim1.py -- Type II retrieval: PinPoint's cascade against whole-function matching.

Reads the type-wise Top-K tables that topk_table.py writes for two runs of the
same subset -- one with the full three-stage cascade, one restricted to Stage 1,
which is whole-function matching and therefore the underlying BCSD backbone on
its own -- and prints them side by side with the paper's full-corpus numbers.

The claim is the gap between the two configurations on Type II, where the
vulnerable function has been inlined away and no longer has a boundary to match.
"""
import argparse
import re
import sys

# Paper Table III, PinPoint-BinShot and the BinShot row it is compared against.
PAPER = {
    'cascade':  {'Type I': (76.1, 79.4, 82.2, 0.781), 'Type II': (65.5, 74.2, 79.8, 0.698),
                 'Type III': (88.3, 90.8, 92.2, 0.895), 'Type IV': (69.6, 79.9, 82.7, 0.742)},
    'baseline': {'Type I': (70.0, 78.6, 82.0, 0.743), 'Type II': (26.9, 41.3, 49.9, 0.342),
                 'Type III': (75.2, 85.2, 87.8, 0.805), 'Type IV': (56.2, 67.1, 76.3, 0.623)},
}
PAPER_N = {'Type I': 3129, 'Type II': 1731, 'Type III': 1122, 'Type IV': 283}
ROW = re.compile(r'^Type (I|II|III|IV)\s*\([^)]*\)\s+(\d+)\s+([\d.]+)%\s+([\d.]+)%\s+([\d.]+)%\s+([\d.]+)')


def parse(path):
    """Type-wise numbers from the last 'db = merged' block of a topk_table report."""
    txt = open(path).read()
    starts = [m.start() for m in re.finditer(r'db = merged', txt)]
    if not starts:
        sys.exit(f'[!] no merged table in {path} -- did topk_table.py run?')
    block = txt[starts[-1]:starts[-1] + 900]
    out = {}
    for line in block.splitlines():
        m = ROW.match(line.strip())
        if m:
            out[f'Type {m.group(1)}'] = (int(m.group(2)), float(m.group(3)),
                                         float(m.group(4)), float(m.group(5)), float(m.group(6)))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--cascade', required=True, help='topk_table output for the full cascade')
    ap.add_argument('--baseline', required=True, help='topk_table output for the Stage-1-only run')
    ap.add_argument('--type', default='Type II')
    args = ap.parse_args()

    casc = parse(args.cascade)
    base = parse(args.baseline)
    t = args.type

    print('=' * 78)
    print(f'CLAIM 1 -- retrieval of {t} targets')
    print('=' * 78)
    print()
    print(f'  {"configuration":<34}{"n":>6}{"Top-1":>9}{"Top-5":>9}{"Top-10":>9}{"MRR":>8}')
    rows = []
    for label, data, paper_key in (
            ('this run: whole-function only', base, 'baseline'),
            ('this run: PinPoint cascade', casc, 'cascade')):
        d = data.get(t)
        if not d:
            print(f'  {label:<34}{"-- not present in this run --":>41}')
            continue
        rows.append((paper_key, d))
        print(f'  {label:<34}{d[0]:>6}{d[1]:>8.1f}%{d[2]:>8.1f}%{d[3]:>8.1f}%{d[4]:>8.3f}')
    print()
    for label, key in (('paper, full corpus: BinShot', 'baseline'),
                       ('paper, full corpus: PinPoint', 'cascade')):
        p = PAPER[key][t]
        print(f'  {label:<34}{PAPER_N[t]:>6}{p[0]:>8.1f}%{p[1]:>8.1f}%{p[2]:>8.1f}%{p[3]:>8.3f}')

    print()
    got = {k: v for k, v in rows}
    if 'baseline' in got and 'cascade' in got:
        gain = got['cascade'][1] - got['baseline'][1]
        paper_gain = PAPER['cascade'][t][0] - PAPER['baseline'][t][0]
        print(f'  Top-1 gain from the sliding-window stages : {gain:+.1f} points '
              f'({got["baseline"][1]:.1f}% -> {got["cascade"][1]:.1f}%)')
        print(f'  the same gain in the paper                : {paper_gain:+.1f} points '
              f'({PAPER["baseline"][t][0]:.1f}% -> {PAPER["cascade"][t][0]:.1f}%)')
        print()
        ok = gain > 0
        print(f'  -> {"PASS" if ok else "FAIL"}  the cascade retrieves {t} targets that '
              f'whole-function matching alone does not')
        return 0 if ok else 1
    print('  -> FAIL  both configurations are needed for this claim')
    return 1


if __name__ == '__main__':
    sys.exit(main())
