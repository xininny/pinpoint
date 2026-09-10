#!/usr/bin/env python3
"""
report_claim1.py -- render Table III (type-wise Top-K retrieval) for this run.

Reads the type-wise tables that topk_table.py writes for two configurations of
the same subset and lays them out in the paper's Table III format: one row per
model, columns grouped by inlining type, then overall.

  Stage 1 only      PinPoint restricted to whole-function comparison, which is
                    what the BCSD backbone does by itself.
  PinPoint-BinShot  the full three-stage cascade.

The paper's full-corpus numbers are printed underneath for reference. Two
caveats on reading them side by side. The subset is far smaller, so no row
matches exactly. And the paper's BinShot row is BinShot evaluated standalone
through its own pipeline, which is close to but not the same as restricting
PinPoint to Stage 1: over the full corpus the two differ by a few points on
Type II. The claim is the gap between the two rows measured here, on identical
binaries, not the distance to the published baseline.
"""
import argparse
import re
import sys

TYPES = ['Type I', 'Type II', 'Type III', 'Type IV']
COLS = TYPES + ['Overall']

# Paper Table III, the two BinShot-based rows.
PAPER = {
    'BinShot': {
        'Type I': (70.0, 78.6, 82.0, 0.743), 'Type II': (26.9, 41.3, 49.9, 0.342),
        'Type III': (75.2, 85.2, 87.8, 0.805), 'Type IV': (56.2, 67.1, 76.3, 0.623),
        'Overall': (58.6, 69.1, 74.1, 0.640)},
    'PinPoint-BinShot': {
        'Type I': (76.1, 79.4, 82.2, 0.781), 'Type II': (65.5, 74.2, 79.8, 0.698),
        'Type III': (88.3, 90.8, 92.2, 0.895), 'Type IV': (69.6, 79.9, 82.7, 0.742),
        'Overall': (72.9, 77.7, 81.0, 0.754)},
}
PAPER_N = {'Type I': 3129, 'Type II': 1731, 'Type III': 1122, 'Type IV': 283, 'Overall': 6451}

_ROW = re.compile(r'^Type (I|II|III|IV)\s*\([^)]*\)\s+(\d+)\s+([\d.]+)%\s+([\d.]+)%\s+([\d.]+)%\s+([\d.]+)')
_TOT = re.compile(r'^Total\s+(\d+)\s+([\d.]+)%\s+([\d.]+)%\s+([\d.]+)%\s+([\d.]+)')


def parse(path):
    """Per-type and overall numbers from the last 'db = merged' block."""
    txt = open(path).read()
    starts = [m.start() for m in re.finditer(r'db = merged', txt)]
    if not starts:
        sys.exit(f'[!] no merged table in {path}; did topk_table.py run?')
    block = txt[starts[-1]:starts[-1] + 900]
    out = {}
    for line in block.splitlines():
        line = line.strip()
        m = _ROW.match(line)
        if m:
            out[f'Type {m.group(1)}'] = (int(m.group(2)), float(m.group(3)),
                                         float(m.group(4)), float(m.group(5)), float(m.group(6)))
            continue
        m = _TOT.match(line)
        if m:
            out['Overall'] = (int(m.group(1)), float(m.group(2)),
                              float(m.group(3)), float(m.group(4)), float(m.group(5)))
    return out


def header():
    top = f'{"":<18}'
    for c in COLS:
        top += f'{c:^25}'
    sub = f'{"Model":<18}'
    for _ in COLS:
        sub += f'{"T1":>6}{"T5":>6}{"T10":>6}{"MRR":>7}'
    return top, sub


def row(label, data, paper=False):
    line = f'{label:<18}'
    for c in COLS:
        if paper:
            v = data.get(c)
            line += f'{v[0]:>6.1f}{v[1]:>6.1f}{v[2]:>6.1f}{v[3]:>7.3f}' if v else f'{"-":>25}'
        else:
            v = data.get(c)
            if not v or v[0] == 0:
                line += f'{"-":>6}{"-":>6}{"-":>6}{"-":>7}'
            else:
                line += f'{v[1]:>6.1f}{v[2]:>6.1f}{v[3]:>6.1f}{v[4]:>7.3f}'
    return line


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--cascade', required=True)
    ap.add_argument('--baseline', required=True)
    args = ap.parse_args()

    casc, base = parse(args.cascade), parse(args.baseline)
    top, sub = header()

    print('TABLE III: Type-wise and overall Top-K function-retrieval accuracy and MRR.')
    print('T1, T5 and T10 denote Top-1, Top-5 and Top-10 accuracy. "Stage 1 only" is')
    print('PinPoint restricted to whole-function comparison, which is what the backbone')
    print('does by itself; PinPoint-BinShot adds the sliding-window stages on top.')
    print()
    print('This run, on the packaged subset:')
    print()
    print(top)
    print(sub)
    print('-' * len(sub))
    print(row('Stage 1 only', base))
    print(row('PinPoint-BinShot', casc))
    print('-' * len(sub))
    ns = f'{"#cases":<18}'
    for c in COLS:
        n = (casc.get(c) or (0,))[0]
        ns += f'{n:>25}'
    print(ns)
    print()
    print('The paper, on the full corpus. Its BinShot row is BinShot evaluated standalone')
    print('through its own pipeline, which is close to but not identical to the Stage 1')
    print('row above; the two differ by a few points on Type II over the full corpus.')
    print()
    print(top)
    print(sub)
    print('-' * len(sub))
    print(row('BinShot', PAPER['BinShot'], paper=True))
    print(row('PinPoint-BinShot', PAPER['PinPoint-BinShot'], paper=True))
    print('-' * len(sub))
    ns = f'{"#cases":<18}'
    for c in COLS:
        ns += f'{PAPER_N[c]:>25}'
    print(ns)

    print()
    t = 'Type II'
    b, c = base.get(t), casc.get(t)
    if not b or not c or b[0] == 0 or c[0] == 0:
        print('  -> FAIL  both configurations are needed for this claim')
        return 1
    gain = c[1] - b[1]
    paper_gain = PAPER['PinPoint-BinShot'][t][0] - PAPER['BinShot'][t][0]
    print(f'  Type II Top-1, this run       : {b[1]:.1f}% -> {c[1]:.1f}%  '
          f'({gain:+.1f} points, n={c[0]})')
    print(f'  Type II Top-1, paper          : {PAPER["BinShot"][t][0]:.1f}% -> '
          f'{PAPER["PinPoint-BinShot"][t][0]:.1f}%  ({paper_gain:+.1f} points, n={PAPER_N[t]})')
    print(f'  the cascade figure to compare : {c[1]:.1f}% here against '
          f'{PAPER["PinPoint-BinShot"][t][0]:.1f}% in the paper')
    print()
    ok = gain > 0
    print(f'  -> {"PASS" if ok else "FAIL"}  the sliding-window stages retrieve Type II targets '
          f'that whole-function matching alone does not')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
