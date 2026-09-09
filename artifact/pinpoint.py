import argparse
import contextlib
import errno
import os
import socket
import subprocess
import sys
import time
import traceback
from glob import glob

_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
_BINSHOT_DIR = os.path.join(_REPO_ROOT, 'binshot')
if _BINSHOT_DIR not in sys.path:
    sys.path.insert(0, _BINSHOT_DIR)

import torch
from tqdm import tqdm

from backbone import (
    MAX_TOKENS, MIN_TOKENS,
    load_model, load_vuln_functions, load_target_functions,
    norm_asm_to_tokens, filter_vuln_indices_by_project_binary,
    parse_target_filename, fmt_score,
)
from stage1_whole_function import run_stage1
from stage2_block_stride import run_stage2
from stage3_token_stride import run_stage3
from report import write_window_dump

import size_based_pruning as _pruning


EARLY_EXIT_THRESHOLD = 0.99

VULN_DB_PATHS = {
    'fno_inline': os.path.join(_REPO_ROOT, 'data', 'reference_db', 'fno_inline.json'),
    'regular':    os.path.join(_REPO_ROOT, 'data', 'reference_db', 'default.json'),
}

VULN_EMBEDDING_PATHS = {
    'fno_inline': os.path.join(_REPO_ROOT, 'data', 'reference_embeddings', 'reference_embeddings_fno_inline.pt'),
    'regular':    os.path.join(_REPO_ROOT, 'data', 'reference_embeddings', 'reference_embeddings_regular.pt'),
}


def load_vuln_embeddings_for_db(db_name):
    emb_path = VULN_EMBEDDING_PATHS.get(db_name)
    if not emb_path or not os.path.exists(emb_path):
        return None
    print(f"[+] Loading pre-computed embeddings for '{db_name}' from {emb_path}")
    data = torch.load(emb_path, map_location='cpu', weights_only=False)
    embeddings = data.get('embeddings', data)
    print(f"[+] Loaded {len(embeddings)} embeddings (mode: {data.get('mode', '?')})")
    return embeddings


def parse_filename_5part(file_name):
    base = file_name.replace('.json', '')
    parts = base.split('-')
    if len(parts) >= 5:
        return parts[0], parts[1], parts[-2], parts[-1]
    if len(parts) == 4:
        return parts[0], parts[1], parts[2], parts[3]
    project = parts[0] if len(parts) > 0 else ''
    binary  = parts[1] if len(parts) > 1 else ''
    compiler = parts[-2] if len(parts) >= 2 else ''
    opt      = parts[-1] if len(parts) >= 1 else ''
    return project, binary, compiler, opt


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def acquire_lock(lock_path):
    payload = f"{socket.gethostname()}:{os.getpid()}".encode()
    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            try:
                os.write(fd, payload)
            finally:
                os.close(fd)
            return lock_path
        except FileExistsError:
            try:
                with open(lock_path, 'r') as f:
                    content = f.read().strip()
                host, _, pid_str = content.partition(':')
                pid = int(pid_str) if pid_str.isdigit() else -1
            except (OSError, ValueError):
                return None
            if host == socket.gethostname() and pid > 0 and not _pid_alive(pid):
                try:
                    os.remove(lock_path)
                    continue
                except FileNotFoundError:
                    continue
                except OSError:
                    return None
            return None
        except OSError as e:
            if e.errno == errno.EEXIST:
                return None
            raise


def release_lock(lock_path):
    if lock_path is None:
        return
    try:
        os.remove(lock_path)
    except FileNotFoundError:
        pass


def rank_targets_for_query(vuln_query, target_functions, model, vocab, device,
                            args, stage_times, stage_counts, filter_stats=None,
                            vuln_emb_entry=None, vuln_idx=-1, file_bar=None):
    vuln_tokens = norm_asm_to_tokens(vuln_query.get('norm_asm', ''))
    vuln_blocks = vuln_query.get('basic_blocks', []) or []

    vuln_bucket = f"stage{vuln_query.get('start_stage', 1)}"
    skip_s1_due_to_flag = (vuln_query.get('start_stage', 1) == 2 and args.stage is None)
    vuln_ntok = len(vuln_tokens)
    filter_enabled = getattr(args, 'filter', True)

    _vuln_emb = {0: vuln_emb_entry} if vuln_emb_entry is not None else None

    work = []
    for t_idx, tfunc in enumerate(target_functions):
        ttokens = norm_asm_to_tokens(tfunc.get('norm_asm', ''))
        tblocks = tfunc.get('basic_blocks', []) or []
        if filter_enabled:
            passed = _pruning.pair_passes(len(ttokens), vuln_ntok)
            if filter_stats is not None:
                filter_stats['candidates'] = filter_stats.get('candidates', 0) + 1
                if passed:
                    filter_stats['kept'] = filter_stats.get('kept', 0) + 1
                    kbf = filter_stats.setdefault('kept_by_flag', {})
                    kbf[vuln_bucket] = kbf.get(vuln_bucket, 0) + 1
                else:
                    filter_stats['skipped'] = filter_stats.get('skipped', 0) + 1
                    sbf = filter_stats.setdefault('skipped_by_flag', {})
                    sbf[vuln_bucket] = sbf.get(vuln_bucket, 0) + 1
        else:
            passed = True
        work.append({
            'target_idx': t_idx,
            'target_func': tfunc,
            'target_tokens': ttokens,
            'target_token_count': len(ttokens),
            'target_block_count': len(tblocks),
            'scores': {},
            'stage_data': {},
            'filter_pass': passed,
        })

    run_stage1_now = (args.stage is None and not skip_s1_due_to_flag) or args.stage == 1
    if run_stage1_now:
        if file_bar is not None:
            file_bar.set_postfix_str("stage1")
        t0 = time.time()
        for wi in work:
            if not wi['filter_pass']:
                continue
            res = run_stage1([vuln_query], wi['target_func'], model, vocab, device,
                              filtered_vuln_indices=[0], vuln_embeddings=_vuln_emb)
            if res:
                wi['scores']['stage1'] = res[0]['score']
                wi['stage_data']['stage1'] = res[0]
                stage_counts['stage1'] += 1
        stage_times['stage1'] += time.time() - t0

    if args.stage == 2:
        pending_s2 = [wi for wi in work if wi['filter_pass']]
    elif args.stage is None:
        if skip_s1_due_to_flag:
            pending_s2 = [wi for wi in work if wi['filter_pass']]
        else:
            pending_s2 = [wi for wi in work
                          if wi['filter_pass']
                          and wi['scores'].get('stage1', 0.0) < EARLY_EXIT_THRESHOLD]
    else:
        pending_s2 = []

    if pending_s2:
        if file_bar is not None:
            file_bar.set_postfix_str("stage2")
        t0 = time.time()
        for wi in pending_s2:
            res = run_stage2([vuln_query], wi['target_func'], model, vocab, device,
                              filtered_vuln_indices=[0], vuln_embeddings=_vuln_emb,
                              stride=args.stage2_stride)
            if res:
                wi['scores']['stage2'] = res[0]['score']
                wi['stage_data']['stage2'] = res[0]
                stage_counts['stage2'] += 1
        stage_times['stage2'] += time.time() - t0

    if args.stage is None:
        pending_s3 = [wi for wi in work
                      if wi['filter_pass']
                      and 'stage2' in wi['scores']
                      and wi['scores']['stage2'] < EARLY_EXIT_THRESHOLD]
    elif args.stage == 3:
        pending_s3 = [wi for wi in work if wi['filter_pass']]
    else:
        pending_s3 = []

    if pending_s3:
        if file_bar is not None:
            file_bar.set_postfix_str("stage3")
        t0 = time.time()
        for wi in pending_s3:
            res = run_stage3([vuln_query], wi['target_func'], model, vocab, device,
                              filtered_vuln_indices=[0], vuln_embeddings=_vuln_emb,
                              stride=args.stage3_stride)
            if res:
                wi['scores']['stage3'] = res[0]['score']
                wi['stage_data']['stage3'] = res[0]
                stage_counts['stage3'] += 1
        stage_times['stage3'] += time.time() - t0

    for wi in work:
        if not wi['scores']:
            wi['best_score'] = 0.0
            wi['best_stage'] = 'none'
            continue
        best_stage = max(wi['scores'], key=wi['scores'].get)
        wi['best_stage'] = best_stage
        wi['best_score'] = wi['scores'][best_stage]

    work.sort(key=lambda x: x['best_score'], reverse=True)
    prev = None
    cur_rank = 0
    for i, wi in enumerate(work):
        if wi['best_score'] != prev:
            cur_rank = i + 1
            prev = wi['best_score']
        wi['rank'] = cur_rank

    wd_entries = []
    for wi in work:
        sd2 = wi['stage_data'].get('stage2')
        sd3 = wi['stage_data'].get('stage3')
        if sd2 is None and sd3 is None:
            continue
        entry = {
            'q': vuln_idx,
            'qf': vuln_query.get('func_name', ''),
            't': wi['target_idx'],
            'tf': wi['target_func'].get('func_name', ''),
            'bs': wi.get('best_stage', 'none'),
        }
        if sd2:
            entry['s2'] = [
                [w['window_start_bb'], w['window_end_bb'],
                 w['target_token_start'], w['target_token_end'], w['window_score']]
                for w in sd2.get('all_window_scores', [])
            ]
        if sd3:
            entry['s3'] = [
                [w['target_start'], w['target_end'], w['window_score']]
                for w in sd3.get('all_window_scores', [])
            ]
        wd_entries.append(entry)

    return {
        'vuln_query': vuln_query,
        'vuln_tokens': vuln_tokens,
        'vuln_token_count': len(vuln_tokens),
        'vuln_block_count': len(vuln_blocks),
        'rankings': work,
        'wd_entries': wd_entries,
    }


def write_report(out_path, metadata, query_results):
    lines = []
    lines.append("=" * 100)
    lines.append("ASM Similarity Report (Vuln-as-Query)")
    lines.append("=" * 100)
    lines.append(f"Target file           : {metadata.get('source_file', '')}")
    lines.append(f"Project/Binary        : {metadata.get('project', '')}/{metadata.get('binary', '')}")
    lines.append(f"Compiler/Opt          : {metadata.get('compiler', '')}/{metadata.get('optimizer_level', '')}")
    lines.append(f"Target functions      : {metadata.get('target_functions', 0)}")
    lines.append(f"Vuln DB               : {metadata.get('vuln_db', '')}")
    lines.append(f"Vuln queries          : {metadata.get('vuln_queries', 0)}")
    lines.append(f"Excluded target opts  : {metadata.get('excluded_opts', [])}")
    lines.append(f"Mode                  : {metadata.get('mode', '')}")
    lines.append(f"Stages                : {metadata.get('stages', [])}")
    lines.append(f"Stage2 stride         : {metadata.get('stage2_stride', '?')}")
    lines.append(f"Stage3 stride         : {metadata.get('stage3_stride', '?')}")
    lines.append(f"Tie-break             : same rank (1, 1, 1, 4, 5 ...)")
    lines.append(f"Status                : {metadata.get('status', 'completed')}")
    if metadata.get('filter_enabled'):
        cand = metadata.get('filter_candidates', 0)
        kept = metadata.get('filter_kept', 0)
        skip = metadata.get('filter_skipped', 0)
        pct = (100 * skip / cand) if cand else 0
        lines.append(f"Filter                : ENABLED  "
                     f"(kept {kept}/{cand}, skipped {skip}/{cand} = {pct:.1f}%)")
        kbf = metadata.get('filter_kept_by_flag', {})
        sbf = metadata.get('filter_skipped_by_flag', {})
        for flag in sorted(set(kbf) | set(sbf)):
            k = kbf.get(flag, 0); s = sbf.get(flag, 0)
            t = k + s; p = (100 * s / t) if t else 0
            lines.append(f"  {flag:<22} kept={k:<6} skipped={s:<6} ({p:.1f}%)")
    else:
        lines.append(f"Filter                : disabled")
    lines.append("")

    total_queries = len(query_results)
    for q_idx, qr in enumerate(query_results, 1):
        vq = qr['vuln_query']
        lines.append("-" * 100)
        lines.append(f"[Query {q_idx}/{total_queries}]")
        lines.append(f"  Vuln func           : {vq.get('func_name', '')}")
        lines.append(f"  Vuln origin         : "
                     f"{vq.get('project', '')}/{vq.get('filename', '')}  "
                     f"{vq.get('compiler', '')}-{vq.get('optimizer_level', '')}")
        lines.append(f"  Vuln CVE            : {vq.get('CVE_ID', [])}")
        start_stage = vq.get('start_stage', 1)
        flag_note = ""
        if start_stage == 2 and metadata.get('stage') is None:
            flag_note = "  (stage 1 skipped — starts from stage 2)"
        lines.append(f"  Vuln start_stage    : {start_stage}{flag_note}")
        lines.append(f"  Vuln tokens/blocks  : {qr['vuln_token_count']} / {qr['vuln_block_count']}")
        lines.append("")
        vuln_tokens = qr.get('vuln_tokens', [])
        s3_stride = metadata.get('stage3_stride', '?')

        lines.append(f"  Full target ranking ({len(qr['rankings'])} functions, ties share rank):")
        lines.append(f"    {'rank':<6} {'score':<6} {'stage':<7} {'func':<40} {'label':<10} tokens")
        for r in qr['rankings']:
            tf = r['target_func']
            fname = tf.get('func_name', '')
            label = tf.get('label', '')
            best_stage = r['best_stage']
            rank_str = f"{r['rank']}."
            lines.append(
                f"    {rank_str:<6} "
                f"{fmt_score(r['best_score']):<6} "
                f"{best_stage:<7} "
                f"{fname:<40} "
                f"{label:<10} "
                f"{r['target_token_count']}"
            )

            scores = r.get('scores', {})
            stage_data = r.get('stage_data', {})
            ttokens_len = r.get('target_token_count', 0)

            sd = stage_data.get(best_stage, {})
            v_start, v_end = 0, 0
            t_start, t_end = 0, 0
            if best_stage == 'stage1':
                v_end = min(len(vuln_tokens), MAX_TOKENS)
                t_end = min(ttokens_len, MAX_TOKENS)
            elif best_stage == 'stage2':
                bs = sd.get('best_window_start', -1)
                be = sd.get('best_window_end', -1)
                lines.append(f"      best window BB     : [{bs}:{be}]")
                v_end = min(len(vuln_tokens), MAX_TOKENS)
                t_start = sd.get('best_target_token_start', 0)
                t_end = sd.get('best_target_token_end', 0)
            elif best_stage == 'stage3':
                ws = sd.get('window_size', 0)
                lines.append(f"      window size/stride : {ws} / {s3_stride}")
                v_end = ws if ws else min(len(vuln_tokens), MAX_TOKENS)
                t_start = sd.get('best_target_start', 0)
                t_end = sd.get('best_target_end', 0)

            lines.append(
                f"      compared range     : "
                f"vuln=[{v_start}:{v_end}] target=[{t_start}:{t_end}]"
            )

            def _s(key):
                v = scores.get(key)
                return f"{v:.2f}" if isinstance(v, (int, float)) else '-'
            lines.append(
                f"      stage scores       : "
                f"stage1={_s('stage1')}  stage2={_s('stage2')}  stage3={_s('stage3')}"
            )
        lines.append("")

    lines.append("=" * 100)
    lines.append("SUMMARY")
    lines.append("=" * 100)
    lines.append(f"Vuln queries processed  : {total_queries}")
    total_time = metadata.get('total_time_sec', 0.0)
    lines.append(f"Total time (sec)        : {total_time:.2f}")
    if total_queries > 0:
        lines.append(f"Avg time per query      : {total_time / total_queries:.2f}")

    stage_times = metadata.get('stage_times_sec') or {}
    stage_counts = metadata.get('stage_counts') or {}
    if stage_times:
        s2_stride = metadata.get('stage2_stride', '?')
        s3_stride = metadata.get('stage3_stride', '?')
        descriptions = {
            'stage1': 'whole function (253-token truncated)',
            'stage2': f'basic-block sliding (stride={s2_stride})',
            'stage3': f'token sliding (stride={s3_stride})',
        }

        lines.append("")
        lines.append("Per-stage execution stats (this target binary):")
        lines.append("  Calls = number of (vuln_query x target_function) pairs that reached the stage.")
        lines.append("  Early-exit: pairs scoring >= 0.99 at a stage skip the remaining stages.")
        lines.append("")
        header = (
            "  | Stage  | Description                              "
            "|   Calls |  Total time |    Avg/call |"
        )
        sep = (
            "  |--------|------------------------------------------"
            "|---------|-------------|-------------|"
        )
        lines.append(header)
        lines.append(sep)

        total_calls = 0
        total_time = 0.0
        for sn in ['stage1', 'stage2', 'stage3']:
            t = stage_times.get(sn)
            c = stage_counts.get(sn, 0)
            if t is None:
                continue
            avg = (t / c) if c else 0.0
            desc = descriptions[sn]
            lines.append(
                f"  | {sn:<6} | {desc:<40} "
                f"| {c:>7} | {t:>9.2f} s | {avg:>9.4f} s |"
            )
            total_calls += c
            total_time += t
        lines.append(sep)
        lines.append(
            f"  | Total  | {'':<40} "
            f"| {total_calls:>7} | {total_time:>9.2f} s | {'':>9}   |"
        )

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')


def process_single_file(json_file, vuln_functions, filtered_vuln_indices,
                         model, vocab, device, args, output_txt_path, vuln_db_label,
                         file_bar=None, bar_prefix="", vuln_embeddings=None):
    target_functions = load_target_functions(json_file)
    if args.max_target_per_file:
        target_functions = target_functions[:args.max_target_per_file]

    file_name = os.path.basename(json_file)
    file_project, file_binary, file_compiler, file_opt = parse_filename_5part(file_name)

    stage_names = []
    if args.stage is None or args.stage == 1:
        stage_names.append('stage1')
    if args.stage is None or args.stage == 2:
        stage_names.append('stage2')
    if args.stage is None or args.stage == 3:
        stage_names.append('stage3')

    metadata = {
        'source_file': file_name,
        'project': file_project,
        'binary': file_binary,
        'compiler': file_compiler,
        'optimizer_level': file_opt,
        'target_functions': len(target_functions),
        'vuln_db': vuln_db_label,
        'vuln_queries': len(filtered_vuln_indices),
        'excluded_opts': list(args.exclude_opt or []),
        'mode': 'ALL vuln queries' if args.all_vuln else 'same project/binary only',
        'stages': stage_names,
        'stage': args.stage,
        'stage2_stride': args.stage2_stride,
        'stage3_stride': args.stage3_stride,
    }

    file_start = time.time()
    stage_times = {'stage1': 0.0, 'stage2': 0.0, 'stage3': 0.0}
    stage_counts = {'stage1': 0, 'stage2': 0, 'stage3': 0}
    filter_enabled = getattr(args, 'filter', True)
    filter_stats = {} if filter_enabled else None

    if file_bar is not None:
        file_bar.reset(total=len(filtered_vuln_indices))
        file_bar.set_description(f"{bar_prefix} {file_name[:30]}")
        file_bar.set_postfix_str("")

    query_results = []
    all_wd_entries = []
    for vuln_idx in filtered_vuln_indices:
        vuln_query = vuln_functions[vuln_idx]
        vuln_emb_entry = vuln_embeddings.get(vuln_idx) if vuln_embeddings is not None else None
        qr = rank_targets_for_query(vuln_query, target_functions, model, vocab, device,
                                     args, stage_times, stage_counts,
                                     filter_stats=filter_stats,
                                     vuln_emb_entry=vuln_emb_entry, vuln_idx=vuln_idx,
                                     file_bar=file_bar)
        query_results.append(qr)
        all_wd_entries.extend(qr.get('wd_entries', []))
        if file_bar is not None:
            file_bar.update(1)

    total_time = time.time() - file_start
    metadata['total_time_sec'] = round(total_time, 2)
    metadata['stage_times_sec'] = {k: round(v, 2) for k, v in stage_times.items()}
    metadata['stage_counts'] = dict(stage_counts)
    metadata['filter_enabled'] = bool(filter_enabled)
    if filter_stats is not None:
        metadata['filter_candidates'] = filter_stats.get('candidates', 0)
        metadata['filter_kept'] = filter_stats.get('kept', 0)
        metadata['filter_skipped'] = filter_stats.get('skipped', 0)
        metadata['filter_kept_by_flag'] = dict(filter_stats.get('kept_by_flag', {}))
        metadata['filter_skipped_by_flag'] = dict(filter_stats.get('skipped_by_flag', {}))
    metadata['status'] = 'completed'

    write_report(output_txt_path, metadata, query_results)

    window_dump_path = None
    if all_wd_entries:
        base = output_txt_path[:-4] if output_txt_path.endswith('.txt') else output_txt_path
        window_dump_path = base + '_windows.jsonl.gz'
        write_window_dump(window_dump_path, {
            'source_file': file_name,
            'stage2_stride': args.stage2_stride,
            'stage3_stride': args.stage3_stride,
        }, all_wd_entries)

    metadata['window_dump_path'] = window_dump_path
    metadata['window_dump_pairs'] = len(all_wd_entries)
    return metadata


def _spawn_workers(n_workers):
    child_argv = []
    skip_next = False
    for tok in sys.argv[1:]:
        if skip_next:
            skip_next = False
            continue
        if tok == '--workers':
            skip_next = True
            continue
        if tok.startswith('--workers='):
            continue
        child_argv.append(tok)

    env = os.environ.copy()
    env['VULN_QUERY_SUPPRESS_PROGRESS'] = '1'

    cmd = [sys.executable, sys.argv[0], '--workers', '1'] + child_argv
    print(f"[+] Spawning {n_workers} worker processes (same GPU, shared via file locks)")

    spawn_start = time.time()
    procs = []
    try:
        for i in range(n_workers):
            child_env = env.copy()
            child_env['VULN_QUERY_WORKER_ID'] = str(i)
            child_env['VULN_QUERY_WORKER_COUNT'] = str(n_workers)
            p = subprocess.Popen(cmd, env=child_env)
            procs.append(p)
        for p in procs:
            p.wait()
    except KeyboardInterrupt:
        print("\n[!] Interrupted - terminating workers...")
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

    total_elapsed = time.time() - spawn_start
    h, rem = divmod(int(total_elapsed), 3600)
    m, s = divmod(rem, 60)
    rcs = [p.returncode for p in procs]
    print(f"[+] All workers exited (return codes: {rcs})")
    print(f"[+] Total wall time: {total_elapsed:.1f}s ({h:02d}:{m:02d}:{s:02d})")
    sys.exit(max((rc for rc in rcs if rc is not None), default=0))


def main():
    parser = argparse.ArgumentParser(
        description='Vuln-as-Query ASM Similarity Calculator')
    parser.add_argument('--vuln_db', type=str, nargs='+',
                        default=list(VULN_DB_PATHS.keys()),
                        choices=list(VULN_DB_PATHS.keys()),
                        help='Vulnerability DB(s) to use. Default: both fno_inline and regular.')
    parser.add_argument('--vuln_path', type=str, default=None,
                        help='Override path to a single vuln DB JSON (disables --vuln_db).')
    parser.add_argument('--data_dir', type=str,
                        default=os.path.join(_REPO_ROOT, 'data', 'targets'),
                        help='Target JSON directory')
    parser.add_argument('--project', type=str, nargs='+', default=None,
                        help='Filter target files by project name(s)')
    parser.add_argument('--sim_model', type=str,
                        default=os.path.join(_REPO_ROOT, 'models', 'binshot_sim.model'))
    parser.add_argument('--vocab_path', type=str,
                        default=os.path.join(_REPO_ROOT, 'models', 'pretrain.all.corpus.voca'))
    parser.add_argument('--output_dir', type=str,
                        default=os.path.join(_REPO_ROOT, 'results'))
    parser.add_argument('--cuda', type=str, default='0')
    parser.add_argument('--stage', type=int, default=None, choices=[1, 2, 3])
    parser.add_argument('--max_files', type=int, default=None)
    parser.add_argument('--max_vuln', type=int, default=None)
    parser.add_argument('--max_target_per_file', type=int, default=None)
    parser.add_argument('--overwrite', action='store_true')
    parser.add_argument('--all-vuln', dest='all_vuln', action='store_true',
                        help='Compare with ALL vuln queries (default: only same project/binary)')
    parser.add_argument('--stage2_stride', '--stride', dest='stage2_stride', type=int, default=1)
    parser.add_argument('--stage3_stride', type=int, default=1)
    parser.add_argument('--exclude_opt', type=str, nargs='+', default=['O0'],
                        help='Optimization levels to EXCLUDE from target files. Default: O0.')
    parser.add_argument('--workers', type=int, default=1)
    parser.add_argument('--filter', dest='filter', action='store_true', default=True,
                        help='Enable pre-filter (minimum code-mass). Default: ON.')
    parser.add_argument('--no-filter', dest='filter', action='store_false',
                        help='Disable pre-filter.')
    args = parser.parse_args()

    if args.workers > 1:
        _spawn_workers(args.workers)
        return

    if args.vuln_path:
        db_targets = [(os.path.basename(args.vuln_path).replace('.json', ''), args.vuln_path)]
    else:
        db_targets = [(db, VULN_DB_PATHS[db]) for db in args.vuln_db]

    run_start = time.time()
    quiet = os.environ.get('VULN_QUERY_SUPPRESS_PROGRESS') == '1'
    setup_ctx = (contextlib.redirect_stdout(open(os.devnull, 'w'))
                 if quiet else contextlib.nullcontext())

    with setup_ctx:
        device = torch.device(f'cuda:{args.cuda}' if torch.cuda.is_available() else 'cpu')
        print(f"[+] Using device: {device}")
        print(f"[+] MAX_TOKENS: {MAX_TOKENS}")
        print(f"[+] Vuln DBs to process: {[d[0] for d in db_targets]}")

        if args.stage is None:
            print(f"[+] Running all stages: Stage 1, 2, 3 (early-exit at >= {EARLY_EXIT_THRESHOLD})")
        else:
            print(f"[+] Running Stage {args.stage} only")

        if getattr(args, 'filter', True):
            print(f"[+] Filter (pre-filter, minimum code-mass): ENABLED  "
                  f"α = {_pruning.ALPHA}")
        else:
            print(f"[+] Filter (pre-filter): DISABLED")

        model, vocab = load_model(args.sim_model, args.vocab_path, device)

        json_files = sorted(glob(os.path.join(args.data_dir, "*.json")))
        if args.project:
            prefixes = tuple(args.project)
            json_files = [f for f in json_files if os.path.basename(f).startswith(prefixes)]
        exclude_opts = [o for o in (args.exclude_opt or []) if o]
        if exclude_opts:
            suffixes = tuple(f"-{opt}.json" for opt in exclude_opts)
            before = len(json_files)
            json_files = [f for f in json_files if not os.path.basename(f).endswith(suffixes)]
            print(f"[+] Excluded {before - len(json_files)} files with opts {exclude_opts} "
                  f"({len(json_files)} remain)")
        if args.max_files:
            json_files = json_files[:args.max_files]
        print(f"[+] Target files to process: {len(json_files)}")
        print(f"[+] Mode: {'ALL vuln queries' if args.all_vuln else 'SAME project/binary only'}")

    total_files = len(json_files)

    db_info = {}
    for db_label, vuln_path in db_targets:
        output_dir = os.path.join(args.output_dir, db_label)
        if args.stage:
            output_dir = os.path.join(output_dir, f'stage{args.stage}')
        os.makedirs(output_dir, exist_ok=True)

        with setup_ctx:
            print(f"\n========== Vuln DB: {db_label} ==========")
            print(f"[+] Path: {vuln_path}")
            print(f"[+] Output dir: {output_dir}")
            vuln_functions = load_vuln_functions(vuln_path)
            if args.max_vuln:
                vuln_functions = vuln_functions[:args.max_vuln]
            print(f"[+] Loaded {len(vuln_functions)} vuln queries from DB")
            vuln_embeddings = load_vuln_embeddings_for_db(db_label)
            if vuln_embeddings is None:
                print(f"[!] No pre-computed embeddings found for '{db_label}' — computing on the fly")

        db_info[db_label] = {
            'output_dir': output_dir,
            'vuln_functions': vuln_functions,
            'vuln_embeddings': vuln_embeddings,
        }

    combined_work = [
        (file_idx, json_file, db_label)
        for file_idx, json_file in enumerate(json_files)
        for db_label, _ in db_targets
    ]
    total_work = len(combined_work)

    worker_id = int(os.environ.get('VULN_QUERY_WORKER_ID', '0'))
    worker_count = max(1, int(os.environ.get('VULN_QUERY_WORKER_COUNT', '1')))

    if worker_count > 1 and total_work > 0:
        offset = (worker_id * total_work) // worker_count
        ordered_work = combined_work[offset:] + combined_work[:offset]
    else:
        ordered_work = combined_work

    worker_tag = f"W{worker_id+1}/{worker_count}" if worker_count > 1 else "Run"

    overall_bar = tqdm(
        total=len(ordered_work), desc=f"{worker_tag} overall",
        position=(worker_id * 2) if worker_count > 1 else 0,
        leave=True, ncols=100,
        bar_format='{desc} {n_fmt}/{total_fmt} [{elapsed}<{remaining}]',
    )
    file_bar = tqdm(
        total=1, desc=f"{worker_tag} (waiting)",
        position=(worker_id * 2 + 1) if worker_count > 1 else 1,
        leave=True, ncols=100,
        bar_format='{desc} {n_fmt}/{total_fmt} {postfix} [{elapsed}]',
    )

    stats = {db_label: {'done': 0, 'exists': 0, 'locked': 0, 'no_vuln': 0} for db_label, _ in db_targets}
    grand_stage_times = {'stage1': 0.0, 'stage2': 0.0, 'stage3': 0.0}
    grand_stage_counts = {'stage1': 0, 'stage2': 0, 'stage3': 0}

    for file_idx, json_file, db_label in ordered_work:
        try:
            info = db_info[db_label]
            output_dir = info['output_dir']
            vuln_functions = info['vuln_functions']
            vuln_embeddings = info['vuln_embeddings']

            file_name = os.path.basename(json_file)
            tag = f"[{db_label}][{file_idx+1}/{total_files}]"
            stage_suffix = f'_stage{args.stage}' if args.stage else ''
            output_txt_file = os.path.join(
                output_dir, f"result_{file_name.replace('.json', f'{stage_suffix}.txt')}")
            lock_file = output_txt_file + '.lock'

            if os.path.exists(output_txt_file) and not args.overwrite:
                stats[db_label]['exists'] += 1
                continue

            lock_handle = acquire_lock(lock_file)
            if lock_handle is None:
                stats[db_label]['locked'] += 1
                continue

            try:
                if os.path.exists(output_txt_file) and not args.overwrite:
                    stats[db_label]['exists'] += 1
                    continue

                file_project, file_binary, _, _ = parse_filename_5part(file_name)
                if args.all_vuln:
                    filtered_vuln_indices = list(range(len(vuln_functions)))
                else:
                    filtered_vuln_indices = filter_vuln_indices_by_project_binary(
                        vuln_functions, file_project, file_binary)
                    if not filtered_vuln_indices:
                        stats[db_label]['no_vuln'] += 1
                        continue

                file_start = time.time()
                bar_prefix = f"{worker_tag} [{db_label}]"
                metadata = process_single_file(
                    json_file, vuln_functions, filtered_vuln_indices,
                    model, vocab, device, args, output_txt_file, db_label,
                    file_bar=file_bar, bar_prefix=bar_prefix,
                    vuln_embeddings=vuln_embeddings,
                )
                elapsed = time.time() - file_start
                wd_pairs = metadata.get('window_dump_pairs', 0)
                wd_msg = f", windows={wd_pairs} pairs" if wd_pairs else ""
                msg = (f"{tag} Done: {file_name}  "
                       f"({metadata['vuln_queries']} queries × {metadata['target_functions']} targets"
                       f"{wd_msg}) in {elapsed:.1f}s")
                tqdm.write(msg)
                stats[db_label]['done'] += 1
                for sn in ('stage1', 'stage2', 'stage3'):
                    grand_stage_times[sn] += metadata.get('stage_times_sec', {}).get(sn, 0.0)
                    grand_stage_counts[sn] += metadata.get('stage_counts', {}).get(sn, 0)
            except Exception as e:
                tqdm.write(f"{tag} ERROR: {file_name}: {e}\n{traceback.format_exc()}")
            finally:
                release_lock(lock_handle)
        finally:
            overall_bar.update(1)

    overall_bar.set_description(f"{worker_tag} overall (done)")
    overall_bar.close()
    file_bar.set_description(f"{worker_tag} (done)")
    file_bar.close()

    total_elapsed = time.time() - run_start
    h, rem = divmod(int(total_elapsed), 3600)
    m, s = divmod(rem, 60)

    grand_done = sum(v['done'] for v in stats.values())
    grand_exists = sum(v['exists'] for v in stats.values())
    grand_locked = sum(v['locked'] for v in stats.values())
    grand_no_vuln = sum(v['no_vuln'] for v in stats.values())

    with setup_ctx:
        for db_label, _ in db_targets:
            v = stats[db_label]
            print(f"[{db_label}] done: processed={v['done']}, "
                  f"exists={v['exists']}, locked={v['locked']}, "
                  f"no_vuln={v['no_vuln']}")

    if worker_count > 1:
        print(f"[worker {worker_id+1}/{worker_count}] grand totals: processed={grand_done}, "
              f"exists={grand_exists}, locked={grand_locked}, no_vuln={grand_no_vuln}, "
              f"time={total_elapsed:.1f}s ({h:02d}:{m:02d}:{s:02d})")
    else:
        print(f"\n[+] All done!")
        print(f"[+] Grand totals: processed={grand_done}, "
              f"exists={grand_exists}, locked={grand_locked}, no_vuln={grand_no_vuln}")
        print(f"[+] Total wall time: {total_elapsed:.1f}s ({h:02d}:{m:02d}:{s:02d})")

    total_stage_calls = sum(grand_stage_counts.values())
    if total_stage_calls:
        print("\n[+] Per-stage totals (this process, all files/DBs processed):")
        for sn in ('stage1', 'stage2', 'stage3'):
            c = grand_stage_counts[sn]
            t = grand_stage_times[sn]
            avg = (t / c) if c else 0.0
            print(f"    {sn}: calls={c:<8} total={t:>9.2f}s avg/call={avg:.4f}s")


if __name__ == '__main__':
    main()
