#!/usr/bin/env python3
"""
build_eval_subset.py -- derive the packaged evaluation subset from the full corpus.

Reviewers do not need to run this; it is shipped so that the derivation of
artifact/data/ from the full corpus is auditable rather than taken on trust.

Selection rule
--------------
The full corpus is 300 target binaries against a 577-entry reference database.
A complete pass took about a week on an H200 with BinShot, and about twice that
with SAFE. The subset keeps the four inlining types in numbers large enough for
the paper's tables to come out close, at a size that fits a Colab session.

Cost here is the sum of both backbones, since Table III reports BinShot and
SAFE on the same binaries. Per-binary costs come from the archived full-corpus
runs. Selection proceeds in three steps.

Type II first. Its accuracy varies widely by project, so binaries are drawn to
reproduce the corpus's project mix for Type II, and within a project at random
(seed 20260911) from those at or below the project's median cost. Always taking
a project's cheapest binaries biased an earlier version of this subset: small
binaries expose few candidate functions, so whole-function matching alone lands
the ground truth inside the top five far more often than it does on the corpus,
and the baseline comes out looking stronger than the paper reports.

Then Type IV, which exists in only 19 binaries corpus-wide, all of them costly.
Only the cheapest is taken. The next ones are readelf builds that each cost more
than the rest of the subset put together, which is why the Type IV row carries
far fewer cases than the others.

Then Types I and III fill the remaining budget, matched to their own project
mixes.

The rule reads only the inlining type, the project, and the cost measured in the
archived runs. It never reads whether PinPoint ranked a case correctly.

Size
----
The rule takes a time budget, and the budget was fixed by one criterion: the
largest subset whose combined BinShot and SAFE runtime stays under four hours on
a Colab T4. That is this 32-binary list, at 1.59 h plus 2.38 h. The next size up
is 33 binaries at 4.86 h, over the target.

Do not cut this list down further. Below 32 binaries the Top-5 ordering of the
two BinShot rows becomes unstable, for the reason given above: the baseline
inflates faster than the cascade as the binaries get smaller, and at 28 and 31
binaries it overtakes PinPoint at Top-5, which the full corpus never does.

The resulting list is frozen in SUBSET below, so the subset is reproducible
without re-running the search.

Usage:
    python3 build_eval_subset.py --paper-root /path/to/full/corpus
"""
import argparse
import json
import os
import re
import shutil
import sys
from collections import defaultdict

# Frozen selection: 32 binaries over 5 projects, 22 CVEs, carrying 65
# ground-truth instances (I 25 / II 32 / III 7 / IV 1).
SUBSET = [
    'coreutils-pr-23-gcc-O3',
    'coreutils-shred-45-gcc-O1',
    'coreutils-split-03-clang-O1',
    'coreutils-split-03-gcc-O1',
    'coreutils-split-03-gcc-O3',
    'libjpeg-cjpeg-98-clang-O1',
    'libjpeg-djpeg-06-gcc-O1',
    'libjpeg-djpeg-64-clang-O1',
    'libjpeg-djpeg-64-clang-O2',
    'libjpeg-djpeg-64-clang-O3',
    'libjpeg-djpeg-64-gcc-O1',
    'libjpeg-djpeg-64-gcc-O2',
    'libjpeg-djpeg-64-gcc-O3',
    'libming-listmp3-64-clang-O2',
    'libming-listmp3-64-clang-O3',
    'libming-listmp3-64-gcc-O1',
    'libming-listmp3-64-gcc-O3',
    'libming-listmp3-65-clang-O2',
    'libming-listmp3-65-clang-O3',
    'libming-listmp3-65-gcc-O1',
    'libming-listmp3-65-gcc-O2',
    'libming-listmp3-65-gcc-O3',
    'libming-listswf-27-clang-O2',
    'libming-listswf-27-gcc-O3',
    'libtiff-tiffcrop-71-gcc-O1',
    'libtiff-tiffcrop-92-gcc-O2',
    'libtiff-tiffinfo-25-clang-O1',
    'libtiff-tiffinfo-25-gcc-O1',
    'libtiff-tiffinfo-25-gcc-O3',
    'libtiff-tiffsplit-95-gcc-O2',
    'zziplib-unzzipcatmem-74-clang-O2',
    'zziplib-unzzipcatmem-74-gcc-O2',
]

# The cheapest binaries of the subset: a few minutes end to end, enough to
# confirm the pipeline runs before committing to the full subset.
SMOKE = [
    'zziplib-unzzipcatmem-74-gcc-O2',
    'coreutils-split-03-gcc-O1',
    'libjpeg-djpeg-06-gcc-O1',
    'libming-listmp3-64-clang-O2',
]

TYPE = {'V': 'I', 'NV-V': 'II', 'V-NV': 'III', 'V-V': 'IV'}
_SEC = re.compile(r'^=== (\S+) ===$')
_ENT = re.compile(r'^  (\S+) \((V|NV-V|V-V|V-NV)\)\s+0x([0-9a-fA-F]+) - 0x([0-9a-fA-F]+)')
_INL = re.compile(r'^\s{4}\[inline #(\d+)\s+(.+?)\]\s+0x([0-9a-fA-F]+) - 0x([0-9a-fA-F]+)')


def parse_gt(path):
    """Ground-truth entries per target build, in the shape the analysis needs."""
    sections = defaultdict(list)
    key = cur = None
    with open(path) as f:
        for line in f:
            line = line.rstrip('\n')
            m = _SEC.match(line)
            if m:
                key = m.group(1); cur = None; continue
            m = _INL.match(line)
            if m and cur is not None:
                inner = re.findall(r'[A-Za-z_][A-Za-z0-9_]*', m.group(2))[-1]
                cur['inlines'].append({'n': int(m.group(1)), 'vuln_func': inner,
                                       'start': int(m.group(3), 16), 'end': int(m.group(4), 16)})
                continue
            m = _ENT.match(line)
            if m:
                cur = {'name': m.group(1), 'label': m.group(2),
                       'start': int(m.group(3), 16), 'end': int(m.group(4), 16),
                       'inlines': []}
                sections[key].append(cur)
    return sections


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    art = os.path.dirname(here)
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--paper-root', required=True)
    ap.add_argument('--ground-truth',
                    help='ground_truth_v3.txt; defaults to <paper-root>/ground_truth_v3.txt')
    ap.add_argument('--out', default=os.path.join(art, 'data'))
    ap.add_argument('--model-out', default=os.path.join(art, 'models'))
    args = ap.parse_args()
    root = args.paper_root

    for sub in ('targets', 'reference_db', 'ground_truth'):
        os.makedirs(os.path.join(args.out, sub), exist_ok=True)

    # ---- targets -------------------------------------------------------
    print('[*] targets')
    projbin = set()
    total = 0
    for name in SUBSET:
        projbin.add((name.split('-')[0], name.split('-')[1]))
        # Only the default builds are targets. The -fno-inline builds exist in
        # the corpus to supply extra *references* for Types II-IV, not to be
        # searched: both reference databases are queried against the same
        # default-build targets, exactly as in the paper's run.
        src = os.path.join(root, 'data', 'json_all', name + '.json')
        if not os.path.exists(src):
            sys.exit(f'[!] missing target: {src}')
        dst = os.path.join(args.out, 'targets', name + '.json')
        shutil.copyfile(src, dst)
        total += os.path.getsize(dst)
    print(f'    {len(SUBSET)} binaries, {total / 2**20:.0f} MiB')

    # ---- references ----------------------------------------------------
    print('[*] reference database')
    srcs = {'default.json': 'data/vuln/vuln_func.json',
            'fno_inline.json': 'data/vuln/vuln_func_fno_inline_flag_regular.json'}
    cves = set()
    for out_name, rel in srcs.items():
        with open(os.path.join(root, rel)) as f:
            allrefs = json.load(f)
        kept = [e for e in allrefs if (e.get('project'), e.get('filename')) in projbin]
        for e in kept:
            cves.update(e.get('CVE_ID') or [])
        with open(os.path.join(args.out, 'reference_db', out_name), 'w') as f:
            json.dump(kept, f)
        print(f'    {out_name}: {len(kept)} entries')
    print(f'    {len(cves)} CVEs')

    # ---- ground truth --------------------------------------------------
    print('[*] ground truth')
    gt = parse_gt(os.path.join(root, 'data', 'gt_address_ranges.txt'))
    kept_gt = {b: gt[b] for b in SUBSET if b in gt}
    missing = [b for b in SUBSET if b not in gt]
    if missing:
        sys.exit(f'[!] no ground truth for: {missing}')
    with open(os.path.join(args.out, 'ground_truth', 'gt_ranges.json'), 'w') as f:
        json.dump(kept_gt, f)

    counts = defaultdict(int)
    instances = []
    for b, ents in kept_gt.items():
        seen = set()
        for e in ents:
            if e['name'] in seen:
                continue
            seen.add(e['name'])
            t = TYPE[e['label']]
            counts[t] += 1
            instances.append({'target': b, 'func': e['name'], 'type': t, 'label': e['label']})
    with open(os.path.join(args.out, 'ground_truth', 'instances.json'), 'w') as f:
        json.dump(instances, f, indent=1)
    n = sum(counts.values())
    print(f'    {n} instances ' + ' '.join(f'{k}={counts[k]}' for k in ('I', 'II', 'III', 'IV')))
    print('    mix ' + ' '.join(f'{k}={counts[k]/n*100:.0f}%' for k in ('I', 'II', 'III', 'IV'))
          + '   (full corpus 47/34/15/3)')

    # The analysis code resolves ground truth through this file, so it travels
    # with the subset rather than being staged by hand.
    gt_v3 = args.ground_truth or os.path.join(root, 'ground_truth_v3.txt')
    if not os.path.exists(gt_v3):
        sys.exit(f'[!] ground truth not found at {gt_v3}; pass --ground-truth')
    shutil.copyfile(gt_v3, os.path.join(args.out, 'ground_truth', 'ground_truth_v3.txt'))
    print('    ground_truth_v3.txt copied')

    with open(os.path.join(args.out, 'ground_truth', 'subset.json'), 'w') as f:
        json.dump({'binaries': SUBSET, 'smoke': SMOKE,
                   'instances_by_type': dict(counts),
                   'corpus_instances_by_type': {'I': 273, 'II': 195, 'III': 89, 'IV': 19},
                   'cves': sorted(cves)}, f, indent=1)

    # ---- model ---------------------------------------------------------
    print('[*] model and vocabulary')
    os.makedirs(args.model_out, exist_ok=True)
    for rel, dst in (('binshot/models/downstream_full/model_sim/sim_ep19.model', 'binshot_sim.model'),
                     ('binshot/pretrain.all.corpus.voca', 'pretrain.all.corpus.voca')):
        src = os.path.join(root, rel)
        if not os.path.exists(src):
            sys.exit(f'[!] missing: {src}')
        out = os.path.join(args.model_out, dst)
        shutil.copyfile(src, out)
        print(f'    {dst}  ({os.path.getsize(out)/2**20:.1f} MiB)')

    print('\n[+] subset written to', args.out)


if __name__ == '__main__':
    main()
