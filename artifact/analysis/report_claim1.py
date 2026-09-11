#!/usr/bin/env python3
"""
report_claim1.py -- render Table III for this run.

Reads the type-wise tables topk_table.py writes for two configurations of the
same subset and lays them out in the paper's Table III format:

  BinShot           Stage 1 only, whole-function comparison, which is what the
                    BCSD backbone does on its own.
  PinPoint-BinShot  the full three-stage cascade.
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
    ap.add_argument('--cascade', required=True)
    ap.add_argument('--baseline', required=True)
    args = ap.parse_args()

    casc, base = parse(args.cascade), parse(args.baseline)
    if not (casc.get('Overall') and base.get('Overall')):
        sys.exit('[!] both the cascade and the Stage 1 tables are needed')

    print('TABLE III: Type-wise and overall Top-K function-retrieval accuracy and MRR of')
    print('PinPoint and the BinShot backbone. For each target-function instance, rank is')
    print('the best rank over all references derived from the same vulnerable function.')
    print('T1, T5 and T10 denote Top-1, Top-5 and Top-10 accuracy. BinShot is evaluated')
    print('standalone, with whole-function matching only; PinPoint-BinShot adds the')
    print('block-stride and token-stride stages. Overall aggregates Types I-IV.')
    print()

    top = f'{"":<18}' + ''.join(f'{c:^25}' for c in COLS)
    sub = f'{"Model":<18}' + f'{"T1":>6}{"T5":>6}{"T10":>6}{"MRR":>7}' * len(COLS)
    print(top)
    print(sub)
    print('-' * len(sub))
    print(row('BinShot', base))
    print(row('PinPoint-BinShot', casc))
    print('-' * len(sub))
    return 0


if __name__ == '__main__':
    sys.exit(main())
