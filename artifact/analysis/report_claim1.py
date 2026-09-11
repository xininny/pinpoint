#!/usr/bin/env python3
"""
report_claim1.py -- render Table III for this run.

Reads the type-wise tables topk_table.py writes for four configurations of the
same subset and lays them out in the paper's Table III format:

  BinShot           Stage 1 only, whole-function comparison, which is what a
  SAFE              BCSD backbone does on its own.
  PinPoint-BinShot  the full three-stage cascade over each backbone.
  PinPoint-SAFE
"""
import argparse
import re
import sys

TYPES = ['Type I', 'Type II', 'Type III', 'Type IV']
COLS = TYPES + ['Overall']

_ROW = re.compile(r'^Type (I|II|III|IV)\s*\([^)]*\)\s+(\d+)\s+([\d.]+)%\s+([\d.]+)%\s+([\d.]+)%\s+([\d.]+)')
_TOT = re.compile(r'^Total\s+(\d+)\s+([\d.]+)%\s+([\d.]+)%\s+([\d.]+)%\s+([\d.]+)')


def parse(path):
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
            out[f'Type {m.group(1)}'] = tuple([int(m.group(2))] + [float(m.group(i)) for i in (3, 4, 5, 6)])
            continue
        m = _TOT.match(line)
        if m:
            out['Overall'] = tuple([int(m.group(1))] + [float(m.group(i)) for i in (2, 3, 4, 5)])
    return out


def row(label, data):
    line = f'{label:<18}'
    for c in COLS:
        v = data.get(c)
        if not v or v[0] == 0:
            line += f'{"-":>6}{"-":>6}{"-":>6}{"-":>7}'
        else:
            line += f'{v[1]:>6.1f}{v[2]:>6.1f}{v[3]:>6.1f}{v[4]:>7.3f}'
    return line


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--binshot-baseline', required=True)
    ap.add_argument('--binshot-cascade', required=True)
    ap.add_argument('--safe-baseline')
    ap.add_argument('--safe-cascade')
    args = ap.parse_args()

    rows = [('BinShot', parse(args.binshot_baseline)),
            ('PinPoint-BinShot', parse(args.binshot_cascade))]
    if args.safe_baseline and args.safe_cascade:
        rows += [('SAFE', parse(args.safe_baseline)),
                 ('PinPoint-SAFE', parse(args.safe_cascade))]
    for label, data in rows:
        if not data.get('Overall'):
            sys.exit(f'[!] no results for the {label} row')

    print('TABLE III: Type-wise and overall Top-K function-retrieval accuracy and MRR of')
    print('PinPoint and the baseline BCSD models. For each target-function instance, rank')
    print('is the best rank over all references derived from the same vulnerable function.')
    print('T1, T5 and T10 denote Top-1, Top-5 and Top-10 accuracy. Each backbone is')
    print('evaluated standalone, with whole-function matching only, and as a PinPoint')
    print('backbone, which adds the block-stride and token-stride stages. Overall')
    print('aggregates Types I-IV.')
    print()

    top = f'{"":<18}' + ''.join(f'{c:^25}' for c in COLS)
    sub = f'{"Model":<18}' + f'{"T1":>6}{"T5":>6}{"T10":>6}{"MRR":>7}' * len(COLS)
    print(top)
    print(sub)
    print('-' * len(sub))
    for label, data in rows:
        print(row(label, data))
    print('-' * len(sub))
    return 0


if __name__ == '__main__':
    sys.exit(main())
