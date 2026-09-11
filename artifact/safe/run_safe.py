#!/usr/bin/env python3
"""
run_safe.py -- PinPoint's cascade over the SAFE backbone.

Same three-stage cascade as artifact/pinpoint.py, with SAFE in place of
BinShot, so that Table III can report both backbones on the same binaries.
What differs is forced by SAFE's architecture, not by choice:

  * SAFE consumes radare2 instructions, not Ghidra tokens, and caps a function
    at 150 instructions where BinShot caps at 253 tokens. Its own limit is used
    here, as in the paper. The packaged SAFE data is therefore a second
    representation of the same 32 binaries; see scripts/build_safe_subset.py.
  * SAFE embeddings are L2-normalized, so cosine similarity is a dot product.
  * Stage 2 slides a window of as many of the reference's own basic blocks as
    fit inside the 150-instruction budget; Stage 3 slides instruction by
    instruction.

Extraction is offline. This script reads the packaged JSON and never invokes
radare2, exactly as pinpoint.py reads Ghidra output and never invokes Ghidra.

Usage:
    python3 run_safe.py --output_dir results/safe [--vuln_db regular fno_inline]
                        [--stage 1] [--overwrite]
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

import numpy as np

_SAFE_DIR = Path(__file__).resolve().parent
_ART_ROOT = _SAFE_DIR.parent
sys.path.insert(0, str(_SAFE_DIR))

from lib import prefilter as PF          # noqa: E402
from lib import window_utils as WU       # noqa: E402
from lib import labels as LBL            # noqa: E402
from lib.cascade import cascade_score    # noqa: E402
from lib.report_writer import write_multistage_report, write_window_dump  # noqa: E402

# SAFE's own input limit, from its published configuration.
MAX_INSTRUCTION = 150
EXCLUDE_OPTS = {'O0'}

DATA = _ART_ROOT / 'data' / 'safe'
MODELS = _ART_ROOT / 'models' / 'safe'
MODEL_PB = MODELS / 'safe_trained_X86.pb'
WORD2ID = MODELS / 'word2id.json'
# install.sh clones SAFE here for its tokenizer and frozen-graph loader.
SAFE_SRC = _ART_ROOT / 'safe_backbone'

DB_FILE = {'regular': 'default.json', 'fno_inline': 'fno_inline.json'}


def compute_included_bb_count(bb_tokens, max_len=MAX_INSTRUCTION):
    """How many of the reference's own basic blocks fit in SAFE's input."""
    if not bb_tokens:
        return 1
    total, count = 0, 0
    for bb in bb_tokens:
        n = len(bb)
        if total + n > max_len:
            if total < max_len:
                count += 1
            break
        total += n
        count += 1
    return max(count, 1)


def flatten_window(bb_tokens, start, k, max_len=MAX_INSTRUCTION):
    """The k blocks from `start`, truncated at SAFE's input limit."""
    toks = []
    for bb in bb_tokens[start:start + k]:
        if len(toks) + len(bb) > max_len:
            toks.extend(bb[:max_len - len(toks)])
            break
        toks.extend(bb)
    return toks


def load_backbone():
    """SAFE's own converter, normalizer and embedder, from its repository."""
    if not SAFE_SRC.exists():
        sys.exit(f'[!] SAFE sources not found at {SAFE_SRC}; run install.sh')
    if not MODEL_PB.exists():
        sys.exit(f'[!] SAFE model not found at {MODEL_PB}; run install.sh\n'
                 '    SAFE is published without a license, so its weights are '
                 'downloaded from\n    the authors\' own distribution rather '
                 'than redistributed here.')
    sys.path.insert(0, str(SAFE_SRC))
    from asm_embedding.InstructionsConverter import InstructionsConverter
    from asm_embedding.FunctionNormalizer import FunctionNormalizer
    from neural_network.SAFEEmbedder import SAFEEmbedder

    converter = InstructionsConverter(str(WORD2ID))
    normalizer = FunctionNormalizer(max_instruction=MAX_INSTRUCTION)
    embedder = SAFEEmbedder(str(MODEL_PB))
    embedder.loadmodel()
    embedder.get_tensor()

    def embed(token_lists):
        converted = [converter.convert_to_ids(x) for x in token_lists]
        normed, lengths = normalizer.normalize_functions(converted)
        return embedder.embedd(np.stack(normed), np.array(lengths))

    return embed


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--vuln_db', nargs='+', default=['regular', 'fno_inline'],
                    choices=['regular', 'fno_inline'])
    ap.add_argument('--output_dir', default=str(_ART_ROOT / 'results' / 'safe'))
    ap.add_argument('--stage', type=int, choices=[1, 2, 3], default=None,
                    help='run only this stage instead of the full cascade')
    ap.add_argument('--stage2_stride', type=int, default=1)
    ap.add_argument('--stage3_stride', type=int, default=1)
    ap.add_argument('--only', nargs='+', metavar='BINARY',
                    help='restrict the run to these target binaries')
    ap.add_argument('--overwrite', action='store_true')
    args = ap.parse_args()

    out_root = Path(args.output_dir)
    targets = sorted(p.stem for p in (DATA / 'targets').glob('*.json')
                     if p.stem.split('-')[-1] not in EXCLUDE_OPTS)
    if args.only:
        targets = [t for t in targets if t in set(args.only)]
    if not targets:
        sys.exit(f'[!] no SAFE target data under {DATA / "targets"}; run install.sh')

    print(f'[+] SAFE backbone, MAX_INSTRUCTION: {MAX_INSTRUCTION}')
    print(f'[+] Vuln DBs to process: {args.vuln_db}')
    print('[+] Running ' + ('all stages: Stage 1, 2, 3 (early-exit at >= 0.99)'
                            if args.stage is None else f'Stage {args.stage} only'))
    print(f'[+] Filter (pre-filter, minimum code-mass): ENABLED  alpha = {PF.PREFILTER_RATIO}')
    print(f'[+] Target files to process: {len(targets)}')

    embed = load_backbone()
    grand = {'processed': 0, 'exists': 0, 'no_vuln': 0}
    stage_totals = {'stage1': 0.0, 'stage2': 0.0, 'stage3': 0.0}
    stage_calls_total = {'stage1': 0, 'stage2': 0, 'stage3': 0}
    t_start = time.time()

    for db in args.vuln_db:
        print(f'\n========== Vuln DB: {db} ==========')
        with open(DATA / 'reference_db' / DB_FILE[db]) as f:
            refs = json.load(f)
        print(f'[+] Loaded {len(refs)} vulnerable functions')
        db_out = out_root / db
        db_out.mkdir(parents=True, exist_ok=True)

        for t_idx, target in enumerate(targets, 1):
            out_path = db_out / (f'result_{target}_stage{args.stage}.txt' if args.stage
                                 else f'result_{target}.txt')
            if args.stage:
                out_path = db_out / f'stage{args.stage}' / out_path.name
                out_path.parent.mkdir(parents=True, exist_ok=True)
            if out_path.exists() and not args.overwrite:
                grand['exists'] += 1
                continue

            parts = target.split('-')
            project, filename = parts[0], parts[1]
            compiler, opt = parts[-2], parts[-1]
            candidates = [v for v in refs
                          if v['entry']['project'] == project
                          and v['entry']['filename'] == filename]
            if not candidates:
                grand['no_vuln'] += 1
                continue

            with open(DATA / 'targets' / f'{target}.json') as f:
                target_funcs = {int(a): d for a, d in json.load(f).items()}
            addrs = list(target_funcs)
            sizes = [len(target_funcs[a]['flat_tokens']) for a in addrs]

            # Stage 1 embeds a candidate's first 150 instructions, which does
            # not depend on the query, so the same function is otherwise
            # re-embedded once per reference. Caching it per binary turns tens
            # of thousands of forward passes into a few hundred.
            #
            # Each is embedded on its own rather than in a batch. Batching
            # would be faster still, but a batched matmul reduces in a
            # different order and moves the last bits of the score. That is
            # invisible in the reported two decimals and cannot change a
            # ranking, but where Stage 1 and Stage 3 see the very same tokens
            # -- a target shorter than the window -- their scores tie exactly,
            # and the tie is broken by stage order. Perturbing it relabels
            # which stage reported the match. Keeping the calls single-item
            # keeps the output identical to a run without this cache.
            s1_cache = {}

            def stage1_embeddings(want):
                for a in want:
                    if a not in s1_cache:
                        s1_cache[a] = embed(
                            [target_funcs[a]['flat_tokens'][:MAX_INSTRUCTION]])[0]
                return s1_cache

            t0 = time.time()
            stage_times = {'stage1': 0.0, 'stage2': 0.0, 'stage3': 0.0}
            stage_calls = {'stage1': 0, 'stage2': 0, 'stage3': 0}
            query_results, wd_entries = [], []
            filt = {'cand': 0, 'kept': 0, 'skip': 0, 'kept_by_flag': {}, 'skip_by_flag': {}}

            for v_idx, v in enumerate(candidates):
                skip_s1 = v['entry'].get('start_stage', 1) == 2
                flag = f"stage{v['entry'].get('start_stage', 1)}"
                vuln_size = len(v['flat_tokens']) or 1
                mask = [PF.passes(s, vuln_size) for s in sizes]
                filt['cand'] += len(mask)
                filt['kept'] += sum(mask)
                filt['skip'] += len(mask) - sum(mask)
                filt['kept_by_flag'][flag] = filt['kept_by_flag'].get(flag, 0) + sum(mask)
                filt['skip_by_flag'][flag] = filt['skip_by_flag'].get(flag, 0) + len(mask) - sum(mask)
                keep_idx = [i for i, m in enumerate(mask) if m]
                if not keep_idx:
                    continue

                v_window = min(vuln_size, MAX_INSTRUCTION)
                v_emb = embed([v['flat_tokens'][:v_window]])[0]
                k_bb = compute_included_bb_count(v['bb_tokens'])

                run_s1 = (args.stage is None and not skip_s1) or args.stage == 1
                if run_s1:
                    t1 = time.time()
                    stage1_embeddings([addrs[i] for i in keep_idx])
                    stage_times['stage1'] += time.time() - t1

                rankings = []
                for i in keep_idx:
                    addr = addrs[i]
                    tf = target_funcs[addr]
                    window_data = {}

                    def stage1_fn(addr=addr):
                        stage_calls['stage1'] += 1
                        return float(np.dot(v_emb, s1_cache[addr]))

                    def stage2_fn(tf=tf):
                        n = len(tf['bb_tokens'])
                        if n == 0:
                            return 0.0, {}
                        t1 = time.time()
                        starts = WU.compute_window_start_range(n, k_bb, args.stage2_stride)
                        bb_lens = [len(bb) for bb in tf['bb_tokens']]
                        bb_off = [sum(bb_lens[:s]) for s in starts]
                        wins = [flatten_window(tf['bb_tokens'], s, k_bb) for s in starts]
                        kept = [(s, o, w) for s, o, w in zip(starts, bb_off, wins) if w]
                        if not kept:
                            return 0.0, {}
                        starts, bb_off, wins = zip(*kept)
                        embs = embed(list(wins))
                        stage_calls['stage2'] += len(wins)
                        stage_times['stage2'] += time.time() - t1
                        sims = embs @ v_emb
                        window_data['s2'] = [
                            [s, min(s + k_bb - 1, n - 1), o, o + len(w), round(float(x), 4)]
                            for s, o, w, x in zip(starts, bb_off, wins, sims)]
                        j = int(np.argmax(sims))
                        return float(sims[j]), {
                            'best_window_start': starts[j],
                            'best_window_end': min(starts[j] + k_bb - 1, n - 1),
                            'target_token_start': bb_off[j],
                            'target_token_end': bb_off[j] + len(wins[j])}

                    def stage3_fn(tf=tf):
                        n = len(tf['flat_tokens'])
                        t1 = time.time()
                        starts = WU.make_sliding_window_starts(n, v_window, args.stage3_stride)
                        wins = [tf['flat_tokens'][s:min(s + v_window, n)] for s in starts]
                        embs = embed(wins)
                        stage_calls['stage3'] += len(wins)
                        stage_times['stage3'] += time.time() - t1
                        sims = embs @ v_emb
                        window_data['s3'] = [[s, min(s + v_window, n), round(float(x), 4)]
                                             for s, x in zip(starts, sims)]
                        j = int(np.argmax(sims))
                        return float(sims[j]), {'window_size': v_window,
                                                'best_target_start': starts[j],
                                                'best_target_end': min(starts[j] + v_window, n)}

                    scores, meta, best = cascade_score(skip_s1, stage1_fn, stage2_fn,
                                                       stage3_fn, force_stage=args.stage)
                    rankings.append({
                        'func_name': tf['func_name'],
                        'label': LBL.get_label('regular', target, tf['func_name'],
                                               start_addr_hex=hex(addr)),
                        'size': sizes[i],
                        'scores': scores, 'best_stage': best,
                        'window_meta': meta.get(best, {})})
                    if window_data:
                        wd_entries.append({'q': v_idx, 'qf': v['entry'].get('func_name', ''),
                                           't': i, 'tf': tf['func_name'], 'bs': best,
                                           **window_data})

                rankings.sort(key=lambda r: -r['scores'][r['best_stage']])
                prev, cur = None, 0
                for i, r in enumerate(rankings):
                    sc = r['scores'][r['best_stage']]
                    if sc != prev:
                        cur, prev = i + 1, sc
                    r['rank'] = cur

                query_results.append({'vuln_func': v['entry'], 'vuln_size': vuln_size,
                                      'vuln_size2': len(v['bb_tokens']),
                                      'skip_stage1': skip_s1, 'rankings': rankings})

            if not query_results:
                grand['no_vuln'] += 1
                continue

            elapsed = time.time() - t0
            metadata = {
                'source_file': f'{target}.json', 'project': project, 'binary': filename,
                'compiler': compiler, 'optimizer_level': opt,
                'target_functions': len(addrs), 'vuln_db': db,
                'vuln_queries': len(query_results),
                'excluded_opts': sorted(EXCLUDE_OPTS), 'mode': 'same project/binary only',
                'model_name': 'SAFE',
                'stages': ['stage1', 'stage2', 'stage3'] if args.stage is None
                          else [f'stage{args.stage}'],
                'stage2_stride': args.stage2_stride, 'stage3_stride': args.stage3_stride,
                'status': 'completed',
                'filter_enabled': True, 'filter_ratio': PF.PREFILTER_RATIO,
                'filter_candidates': filt['cand'], 'filter_kept': filt['kept'],
                'filter_skipped': filt['skip'],
                'filter_kept_by_flag': filt['kept_by_flag'],
                'filter_skipped_by_flag': filt['skip_by_flag'],
                'total_time_sec': elapsed,
                'stage_times_sec': {k: round(v, 2) for k, v in stage_times.items()},
                'stage_counts': stage_calls}
            write_multistage_report(out_path, metadata, query_results)
            if wd_entries and args.stage is None:
                write_window_dump(out_path.parent / f'result_{target}_windows.jsonl.gz',
                                  {'source_file': f'{target}.json',
                                   'stage2_stride': args.stage2_stride,
                                   'stage3_stride': args.stage3_stride}, wd_entries)
            grand['processed'] += 1
            for k in stage_totals:
                stage_totals[k] += stage_times[k]
                stage_calls_total[k] += stage_calls[k]
            print(f'[{db}][{t_idx}/{len(targets)}] Done: {target}.json  '
                  f'({len(query_results)} queries x {len(addrs)} targets) in {elapsed:.1f}s',
                  flush=True)

    total = time.time() - t_start
    h, rem = divmod(int(total), 3600)
    m, s = divmod(rem, 60)
    print('\n[+] All done!')
    print(f'[+] Grand totals: processed={grand["processed"]}, '
          f'exists={grand["exists"]}, no_vuln={grand["no_vuln"]}')
    print(f'[+] Total wall time: {total:.1f}s ({h:02d}:{m:02d}:{s:02d})')
    print('\n[+] Per-stage totals (this process, all files/DBs processed):')
    for k in ('stage1', 'stage2', 'stage3'):
        c, t = stage_calls_total[k], stage_totals[k]
        print(f'    {k}: calls={c:<8} total={t:>9.2f}s '
              f'avg/call={(t / c if c else 0.0):.4f}s')


if __name__ == '__main__':
    main()
