import os
import sys
import json
import argparse
import torch
from tqdm import tqdm

from backbone import (
    MAX_TOKENS, MIN_TOKENS,
    load_model, norm_asm_to_tokens
)
from stage1_whole_function import precompute_vuln_embedding
from stage2_block_stride import precompute_vuln_bb_embedding
from stage3_token_stride import precompute_vuln_stride1_embedding

_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))


VULN_DB_PATHS = {
    'fno_inline': os.path.join(_REPO_ROOT, 'data', 'reference_db', 'fno_inline.json'),
    'regular':    os.path.join(_REPO_ROOT, 'data', 'reference_db', 'default.json'),
}


def precompute_unified(vuln_functions, model, vocab, device):
    print(f"[+] Pre-computing UNIFIED embeddings for all stages...")
    print(f"    - Stage 1/2: emb (253 token truncated)")
    print(f"    - Stage 2: num_blocks (sliding window size k)")
    print(f"    - Stage 3: stage3_emb (single embedding, target slides)")

    embeddings = {}
    total_valid = 0
    skipped_short = 0
    total_bb_count = 0
    stage3_valid = 0

    for idx, vuln_func in enumerate(tqdm(vuln_functions, desc="  Computing")):
        vuln_tokens = norm_asm_to_tokens(vuln_func.get('norm_asm', ''))

        metadata = {
            'project': vuln_func.get('project', ''),
            'filename': vuln_func.get('filename', ''),
            'func_name': vuln_func.get('func_name', ''),
            'compiler': vuln_func.get('compiler', ''),
            'optimizer_level': vuln_func.get('optimizer_level', ''),
            'CVE_ID': vuln_func.get('CVE_ID', []),
            'start_stage': vuln_func.get('start_stage', 1),
            'token_count': len(vuln_tokens) if vuln_tokens else 0,
            'norm_asm': vuln_func.get('norm_asm', ''),
            'basic_blocks': vuln_func.get('basic_blocks', []),
        }

        if not vuln_tokens or len(vuln_tokens) <= MIN_TOKENS:
            skipped_short += 1
            embeddings[idx] = {
                **metadata,
                'emb': None,
                'num_blocks': 0,
                'stage3_emb': None,
                'window_size': 0,
                'status': 'too_short',
            }
            continue

        stage2_result = precompute_vuln_bb_embedding(vuln_func, model, vocab, device)

        stage3_result = precompute_vuln_stride1_embedding(vuln_func, model, vocab, device)

        if stage2_result is None and stage3_result is None:
            skipped_short += 1
            embeddings[idx] = {
                **metadata,
                'emb': None,
                'num_blocks': 0,
                'stage3_emb': None,
                'window_size': 0,
                'status': 'emb_failed',
            }
            continue

        entry = {
            **metadata,
            'status': 'ok',
        }

        if stage2_result:
            entry['emb'] = stage2_result['emb']
            entry['num_blocks'] = stage2_result.get('num_blocks', 1)
            entry['original_num_blocks'] = stage2_result.get('original_num_blocks', 1)
            total_bb_count += entry['num_blocks']
        else:
            entry['emb'] = None
            entry['num_blocks'] = 0

        if stage3_result:
            entry['stage3_emb'] = stage3_result['emb']
            entry['window_size'] = stage3_result.get('window_size', 0)
            stage3_valid += 1
        else:
            entry['stage3_emb'] = None
            entry['window_size'] = 0

        embeddings[idx] = entry
        total_valid += 1

    stats = {
        'total_functions': len(vuln_functions),
        'total_valid': total_valid,
        'skipped_short': skipped_short,
        'total_bb_count': total_bb_count,
        'avg_bb_per_func': total_bb_count / total_valid if total_valid > 0 else 0,
        'stage3_valid': stage3_valid,
    }

    return embeddings, stats


def _fallback_metadata(vuln_func, vuln_tokens):
    return {
        'token_count': len(vuln_tokens) if vuln_tokens else 0,
        'project': vuln_func.get('project', ''),
        'filename': vuln_func.get('filename', ''),
        'func_name': vuln_func.get('func_name', ''),
        'compiler': vuln_func.get('compiler', ''),
        'optimizer_level': vuln_func.get('optimizer_level', ''),
        'CVE_ID': vuln_func.get('CVE_ID', []),
        'start_stage': vuln_func.get('start_stage', 1),
        'norm_asm': vuln_func.get('norm_asm', ''),
        'basic_blocks': vuln_func.get('basic_blocks', []),
    }


def precompute_stage1(vuln_functions, model, vocab, device):
    print(f"[+] Pre-computing Stage 1 embeddings (253 token truncated)...")

    embeddings = {}
    total_valid = 0
    skipped_short = 0

    for idx, vuln_func in enumerate(tqdm(vuln_functions, desc="  Stage 1")):
        result = precompute_vuln_embedding(vuln_func, model, vocab, device)

        if result is None:
            skipped_short += 1
            vuln_tokens = norm_asm_to_tokens(vuln_func.get('norm_asm', ''))
            embeddings[idx] = {
                'emb': None,
                'status': 'too_short',
                **_fallback_metadata(vuln_func, vuln_tokens),
            }
        else:
            embeddings[idx] = result
            embeddings[idx]['status'] = 'ok'
            total_valid += 1

    stats = {
        'total_functions': len(vuln_functions),
        'total_valid': total_valid,
        'skipped_short': skipped_short,
    }

    return embeddings, stats


def precompute_stage2(vuln_functions, model, vocab, device):
    print(f"[+] Pre-computing Stage 2 embeddings (Basic Block based)...")

    embeddings = {}
    total_valid = 0
    skipped_short = 0
    total_bb_count = 0

    for idx, vuln_func in enumerate(tqdm(vuln_functions, desc="  Stage 2")):
        result = precompute_vuln_bb_embedding(vuln_func, model, vocab, device)

        if result is None:
            skipped_short += 1
            vuln_tokens = norm_asm_to_tokens(vuln_func.get('norm_asm', ''))
            embeddings[idx] = {
                'emb': None,
                'num_blocks': 0,
                'status': 'too_short',
                **_fallback_metadata(vuln_func, vuln_tokens),
            }
        else:
            embeddings[idx] = result
            embeddings[idx]['status'] = 'ok'
            total_valid += 1
            total_bb_count += result.get('num_blocks', 0)

    stats = {
        'total_functions': len(vuln_functions),
        'total_valid': total_valid,
        'skipped_short': skipped_short,
        'total_bb_count': total_bb_count,
        'avg_bb_per_func': total_bb_count / total_valid if total_valid > 0 else 0,
    }

    return embeddings, stats


def precompute_stage3(vuln_functions, model, vocab, device, stride=1):
    print(f"[+] Pre-computing Stage 3 embeddings (vuln fixed, target slides)...")

    embeddings = {}
    total_valid = 0
    skipped_short = 0

    for idx, vuln_func in enumerate(tqdm(vuln_functions, desc="  Stage 3")):
        result = precompute_vuln_stride1_embedding(vuln_func, model, vocab, device)

        if result is None:
            skipped_short += 1
            vuln_tokens = norm_asm_to_tokens(vuln_func.get('norm_asm', ''))
            embeddings[idx] = {
                'emb': None,
                'window_size': 0,
                'status': 'too_short',
                **_fallback_metadata(vuln_func, vuln_tokens),
            }
        else:
            embeddings[idx] = result
            embeddings[idx]['status'] = 'ok'
            total_valid += 1

    stats = {
        'total_functions': len(vuln_functions),
        'total_valid': total_valid,
        'skipped_short': skipped_short,
    }

    return embeddings, stats


def print_stats(mode, stats):
    print(f"\n[+] Statistics ({mode}):")
    print(f"    Total functions:      {stats['total_functions']}")
    print(f"    Valid functions:      {stats['total_valid']} (>{MIN_TOKENS} tokens)")
    print(f"    Skipped (too short):  {stats['skipped_short']}")

    if 'total_bb_count' in stats:
        print(f"    Total BB count:       {stats['total_bb_count']}")
        print(f"    Avg BB/func:          {stats['avg_bb_per_func']:.2f}")

    if 'stage3_valid' in stats:
        print(f"    Stage 3 valid:        {stats['stage3_valid']}")


def print_flag_breakdown(vuln_functions):
    counts = {}
    for v in vuln_functions:
        stage = v.get('start_stage', 1)
        counts[stage] = counts.get(stage, 0) + 1
    print(f"[+] start_stage breakdown: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))


def save_embeddings(data, output_path, mode):
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    print(f"\n[+] Saving {mode} embeddings to {output_path} ...")
    torch.save(data, output_path)

    size_mb = os.path.getsize(output_path) / 1024 / 1024
    print(f"[+] Done! File size: {size_mb:.1f} MB")


def run_for_db(db_name, vuln_path, model, vocab, device, args, output_path):
    print(f"\n{'='*60}")
    print(f"Vuln DB: {db_name}  ({vuln_path})")
    print(f"{'='*60}")

    print(f"[+] Loading vuln functions from {vuln_path}")
    with open(vuln_path, 'r') as f:
        vuln_functions = json.load(f)
    print(f"[+] Loaded {len(vuln_functions)} vuln functions")
    print_flag_breakdown(vuln_functions)

    has_bb = any('basic_blocks' in v for v in vuln_functions)
    if has_bb:
        print(f"[+] Found basic_blocks field in vuln data")
    else:
        print(f"[!] No basic_blocks field found - Stage 2 will treat each function as single block")

    if args.stage is None:
        print(f"[+] UNIFIED MODE: Generating embeddings for ALL stages")

        embeddings, stats = precompute_unified(vuln_functions, model, vocab, device)
        mode = 'unified'
        print_stats('unified', stats)

        data = {
            'embeddings': embeddings,
            'mode': 'unified',
            'stages': [1, 2, 3],
            'max_tokens': MAX_TOKENS,
            'min_tokens': MIN_TOKENS,
            'vuln_db': db_name,
            'vuln_path': vuln_path,
            'sim_model_path': args.sim_model,
            'vocab_path': args.vocab_path,
            'stats': stats,
        }

        save_embeddings(data, output_path, 'unified')
        print(f"\n[+] Usage with sim_cal.py (all stages supported):")
        print(f"    python3 sim_cal.py --cuda {args.cuda} --embeddings {output_path}")

    else:
        print(f"[+] Stage {args.stage} only")

        if args.stage == 1:
            embeddings, stats = precompute_stage1(vuln_functions, model, vocab, device)
            mode = 'stage1_truncated'
        elif args.stage == 2:
            embeddings, stats = precompute_stage2(vuln_functions, model, vocab, device)
            mode = 'stage2_basicblock'
        elif args.stage == 3:
            embeddings, stats = precompute_stage3(vuln_functions, model, vocab, device)
            mode = 'stage3_fixed_vuln'

        print_stats(f'stage{args.stage}', stats)

        data = {
            'embeddings': embeddings,
            'stage': args.stage,
            'mode': mode,
            'max_tokens': MAX_TOKENS,
            'min_tokens': MIN_TOKENS,
            'vuln_db': db_name,
            'vuln_path': vuln_path,
            'sim_model_path': args.sim_model,
            'vocab_path': args.vocab_path,
            'stats': stats,
        }

        save_embeddings(data, output_path, f'stage{args.stage}')
        print(f"\n[+] Usage with sim_cal.py:")
        print(f"    python3 sim_cal.py --cuda {args.cuda} --stage {args.stage} --embeddings {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Pre-compute vuln embeddings for all stages')
    parser.add_argument('--vuln_db', type=str, nargs='+',
                        default=list(VULN_DB_PATHS.keys()),
                        choices=list(VULN_DB_PATHS.keys()),
                        help='Vulnerability DB(s) to precompute embeddings for. '
                             'Default: both fno_inline and regular.')
    parser.add_argument('--vuln_path', type=str, default=None,
                        help='Override: path to a single custom vuln DB JSON (disables --vuln_db).')
    parser.add_argument('--sim_model', type=str,
                        default=os.path.join(_REPO_ROOT, 'models', 'binshot_sim.model'))
    parser.add_argument('--vocab_path', type=str,
                        default=os.path.join(_REPO_ROOT, 'models', 'pretrain.all.corpus.voca'))
    parser.add_argument('--output_dir', type=str,
                        default=os.path.join(_REPO_ROOT, 'data', 'reference_embeddings'),
                        help='Output directory for embeddings files')
    parser.add_argument('--output', type=str, default=None,
                        help='Output path (overrides output_dir). Only valid when exactly one '
                             'vuln DB is selected (--vuln_db with one value, or --vuln_path).')
    parser.add_argument('--cuda', type=str, default='0')
    parser.add_argument('--stage', type=int, default=None, choices=[1, 2, 3],
                        help='Generate only specific stage embeddings. '
                             'Default: unified embeddings for all stages')
    parser.add_argument('--stride', type=int, default=1,
                        help='Sliding window stride for Stage 3 (default: 1)')

    args = parser.parse_args()

    if args.vuln_path:
        db_targets = [(os.path.basename(args.vuln_path).replace('.json', ''), args.vuln_path)]
    else:
        db_targets = [(db, VULN_DB_PATHS[db]) for db in args.vuln_db]

    if args.output and len(db_targets) > 1:
        parser.error('--output can only be used when exactly one vuln DB is selected '
                      '(pass --vuln_db with a single value, or --vuln_path).')

    device = torch.device(f'cuda:{args.cuda}' if torch.cuda.is_available() else 'cpu')
    print(f"[+] Using device: {device}")
    print(f"[+] MAX_TOKENS: {MAX_TOKENS}")
    print(f"[+] MIN_TOKENS: {MIN_TOKENS}")
    print(f"[+] Vuln DBs to process: {[d[0] for d in db_targets]}")

    model, vocab = load_model(args.sim_model, args.vocab_path, device)

    for db_name, vuln_path in db_targets:
        if args.output:
            output_path = args.output
        elif args.stage is None:
            # must match VULN_EMBEDDING_PATHS in pinpoint.py, which is where
            # the cascade looks for these; a mismatch here is silent -- the run
            # just recomputes every reference embedding for every candidate
            output_path = os.path.join(args.output_dir, f'reference_embeddings_{db_name}.pt')
        else:
            output_path = os.path.join(args.output_dir, f'reference_embeddings_stage{args.stage}_{db_name}.pt')

        run_for_db(db_name, vuln_path, model, vocab, device, args, output_path)

    print(f"\n{'='*60}")
    print(f"[+] All done! ({len(db_targets)} DB(s) processed)")


if __name__ == '__main__':
    main()
