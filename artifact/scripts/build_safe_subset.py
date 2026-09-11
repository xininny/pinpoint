#!/usr/bin/env python3
"""
build_safe_subset.py -- derive the packaged SAFE data from the full corpus.

Table III reports two backbones, and they do not share a preprocessing
pipeline: BinShot reads Ghidra output, SAFE reads radare2 output through its
own normalizer. So the same 32 binaries appear twice under artifact/data/,
once in each representation.

Like the Ghidra side, extraction happens offline and only its result ships, so
that reviewers need neither radare2 nor a multi-hour re-extraction. Two things
are written:

    safe/targets/<binary>.json    every function of a target binary, as
                                  {address: {func_name, bb_tokens,
                                  flat_tokens}}.

    safe/reference_db/<db>.json   only the vulnerable functions, resolved from
                                  their origin binaries and carried with the
                                  metadata the cascade needs. Shipping the
                                  origin binaries whole would cost 233 MiB to
                                  deliver a few hundred functions.

Reviewers do not need to run this. It is shipped so that the SAFE data is
auditable in the same way the Ghidra data is.

Usage:
    python3 build_safe_subset.py --safe-root /path/to/SAFE --paper-root /path/to/corpus
"""
import argparse
import json
import os
import shutil
import sys

TOKEN_FIELDS = ('func_name', 'bb_tokens', 'flat_tokens')
# The cascade reads these off each reference; the rest of a vuln_func.json row
# is assembly text that SAFE never looks at.
ENTRY_FIELDS = ('project', 'filename', 'compiler', 'optimizer_level',
                'func_name', 'start_addr', 'CVE_ID', 'start_stage')


def origin_binary(entry, num):
    """{project}-{filename}-{num}-{compiler}-{opt}, num zero-padded to two."""
    num_str = f'{num:02d}' if isinstance(num, int) else str(num)
    return (f"{entry['project']}-{entry['filename']}-{num_str}"
            f"-{entry['compiler']}-{entry['optimizer_level']}")


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    art = os.path.dirname(here)
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--safe-root', required=True,
                    help="SAFE checkout holding reproduce/extract_cache/")
    ap.add_argument('--paper-root', required=True)
    ap.add_argument('--out', default=os.path.join(art, 'data', 'safe'))
    args = ap.parse_args()

    with open(os.path.join(art, 'data', 'ground_truth', 'subset.json')) as f:
        subset = json.load(f)['binaries']
    cache = os.path.join(args.safe_root, 'reproduce', 'extract_cache')

    # ---- targets --------------------------------------------------------
    print('[*] targets')
    tdir = os.path.join(args.out, 'targets')
    os.makedirs(tdir, exist_ok=True)
    total = 0
    for b in subset:
        src = os.path.join(cache, 'regular', b + '.json')
        if not os.path.exists(src):
            sys.exit(f'[!] missing SAFE extraction: {src}')
        dst = os.path.join(tdir, b + '.json')
        shutil.copyfile(src, dst)
        total += os.path.getsize(dst)
    print(f'    {len(subset)} binaries, {total / 2**20:.0f} MiB')

    # ---- reference databases -------------------------------------------
    print('[*] reference databases')
    rdir = os.path.join(args.out, 'reference_db')
    os.makedirs(rdir, exist_ok=True)
    projbin = {(b.split('-')[0], b.split('-')[1]) for b in subset}
    with open(os.path.join(args.paper_root, 'data', 'vuln', 'vuln_func_info.json')) as f:
        cve_to_num = {row['cve']: row['num'] for row in json.load(f)}

    srcs = {'default': 'data/vuln/vuln_func.json',
            'fno_inline': 'data/vuln/vuln_func_fno_inline_flag_regular.json'}
    # 'default' reads reference functions out of the default builds,
    # 'fno_inline' out of the -fno-inline builds of the same programs.
    cache_kind = {'default': 'regular', 'fno_inline': 'fno_inline'}

    binaries = {}

    def funcs_of(name, kind):
        key = (name, kind)
        if key not in binaries:
            path = os.path.join(cache, kind, name + '.json')
            if not os.path.exists(path):
                binaries[key] = {}
            else:
                with open(path) as f:
                    binaries[key] = {int(a): d for a, d in json.load(f).items()}
        return binaries[key]

    for out_name, rel in srcs.items():
        with open(os.path.join(args.paper_root, rel)) as f:
            entries = json.load(f)
        kept, unresolved = [], 0
        for e in entries:
            if (e.get('project'), e.get('filename')) not in projbin:
                continue
            cves = e.get('CVE_ID') or []
            if not cves or cves[0] not in cve_to_num:
                continue
            name = origin_binary(e, cve_to_num[cves[0]])
            fn = funcs_of(name, cache_kind[out_name]).get(int(e['start_addr']))
            if fn is None:
                # radare2 did not recover a function at that address in this
                # build; the same entry is simply absent from SAFE's run.
                unresolved += 1
                continue
            kept.append({'entry': {k: e[k] for k in ENTRY_FIELDS if k in e},
                         'origin_binary': name,
                         **{k: fn[k] for k in TOKEN_FIELDS}})
        out = os.path.join(rdir, out_name + '.json')
        with open(out, 'w') as f:
            json.dump(kept, f)
        print(f'    {out_name}.json: {len(kept)} entries, {unresolved} unresolved, '
              f'{os.path.getsize(out) / 2**20:.1f} MiB')

    print('\n[+] SAFE data written to', args.out)


if __name__ == '__main__':
    main()
