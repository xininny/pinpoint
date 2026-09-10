#!/usr/bin/env python3
"""
build_eval_subset.py -- derive the packaged evaluation subset from the full corpus.

Reviewers do not need to run this; it is shipped so that the derivation of
artifact/data/ from the full corpus is auditable rather than taken on trust.

Selection rule
--------------
The full corpus is 300 target binaries carrying 596 ground-truth
target-function instances, and running all of it takes about a week on one
GPU. The subset keeps ~10% of those instances while preserving their
composition across the four inlining types.

Binaries are chosen by a cost-aware greedy pass over per-type instance quotas:
at each step it takes the binary that supplies the most still-needed instances
per second of measured runtime, subject to a cap on how many builds of the same
binary and how large a share of one project may be taken. Runtime comes from
the archived full-corpus run, so the selection depends only on cost and on the
inlining type of each instance -- never on whether PinPoint got that instance
right. The resulting binary list is frozen in SUBSET below so the subset is
reproducible without re-running the search.

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

# Frozen selection: 34 binaries, 58 instances (I 27 / II 20 / III 10 / IV 1),
# 5 projects, 20 CVEs. Composition 47/34/17/2 % against the corpus 47/34/15/3 %.
SUBSET = [
    'coreutils-pr-23-gcc-O3',
    'coreutils-shred-45-clang-O2',
    'coreutils-shred-45-gcc-O1',
    'coreutils-split-03-clang-O1',
    'coreutils-split-03-gcc-O1',
    'coreutils-split-03-gcc-O2',
    'coreutils-split-03-gcc-O3',
    'libarchive-bsdtar-44-gcc-O2',
    'libarchive-bsdtar-49-clang-O2',
    'libarchive-bsdtar-49-gcc-O1',
    'libarchive-bsdtar-49-gcc-O2',
    'libjpeg-cjpeg-98-clang-O1',
    'libjpeg-cjpeg-98-clang-O2',
    'libjpeg-cjpeg-98-clang-O3',
    'libjpeg-cjpeg-98-gcc-O1',
    'libjpeg-cjpeg-98-gcc-O2',
    'libjpeg-cjpeg-98-gcc-O3',
    'libjpeg-djpeg-06-gcc-O1',
    'libjpeg-djpeg-06-gcc-O2',
    'libjpeg-djpeg-64-clang-O1',
    'libjpeg-djpeg-64-clang-O2',
    'libjpeg-djpeg-64-clang-O3',
    'libjpeg-djpeg-64-gcc-O1',
    'libjpeg-djpeg-64-gcc-O2',
    'libjpeg-djpeg-64-gcc-O3',
    'libming-listmp3-64-clang-O1',
    'libming-listmp3-64-clang-O2',
    'libming-listmp3-64-clang-O3',
    'libming-listmp3-64-gcc-O1',
    'libming-listmp3-64-gcc-O2',
    'libming-listmp3-64-gcc-O3',
    'libming-listmp3-65-clang-O1',
    'libming-listmp3-65-clang-O2',
    'libming-listmp3-65-clang-O3',
    'libming-listmp3-65-gcc-O1',
    'libming-listmp3-65-gcc-O2',
    'libming-listmp3-65-gcc-O3',
    'libming-listswf-27-clang-O2',
    'libming-listswf-27-gcc-O3',
    'libtiff-tiffcrop-21-clang-O1',
    'libtiff-tiffcrop-21-clang-O2',
    'libtiff-tiffcrop-21-clang-O3',
    'libtiff-tiffcrop-71-gcc-O1',
    'libtiff-tiffcrop-92-clang-O1',
    'libtiff-tiffcrop-92-clang-O2',
    'libtiff-tiffcrop-92-gcc-O1',
    'libtiff-tiffcrop-92-gcc-O2',
    'libtiff-tiffinfo-25-clang-O1',
    'libtiff-tiffinfo-25-gcc-O1',
    'libtiff-tiffinfo-25-gcc-O3',
    'libtiff-tiffmedian-11-clang-O1',
    'libtiff-tiffmedian-11-gcc-O1',
    'libtiff-tiffsplit-95-gcc-O2',
    'zziplib-unzzipcatmem-74-clang-O2',
    'zziplib-unzzipcatmem-74-gcc-O1',
    'zziplib-unzzipcatmem-74-gcc-O2',
]

# A handful of the cheapest binaries, for the minutes-long smoke run.
# The cheapest binaries carrying Type II cases: a few minutes end to end,
# enough to confirm the pipeline works before committing to the full subset.
# The cheapest binaries, for a quick end-to-end check.
SMOKE = [
    'zziplib-unzzipcatmem-74-gcc-O2',
    'coreutils-split-03-gcc-O2',
    'libjpeg-djpeg-06-gcc-O2',
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
