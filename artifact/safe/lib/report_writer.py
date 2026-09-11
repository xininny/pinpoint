#!/usr/bin/env python3
"""
BinShot-format report writer, reused as-is (same header/section layout as
artifact/pinpoint.py's write_report()) for baseline
models that only reproduce the Stage-1 equivalent (single whole-function
embedding vs. whole-function embedding, no BB/token sliding window):
HermesSim, VulHawk, trex, B7_safe/SAFE.

Every section BinShot's report has is kept, in the same order — Stage 2/3
lines are kept but marked 'N/A' rather than removed, so the file stays
structurally diffable against a real BinShot report.
"""

import gzip
import json
from pathlib import Path


def fmt_score(score):
    if score is None:
        return '-'
    return f'{score:.2f}'


def write_stage1_report(out_path, metadata, query_results):
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
    lines.append(f"Model                 : {metadata.get('model_name', '')}")
    lines.append(f"Stages                : {metadata.get('stages', ['stage1'])}")
    lines.append(f"Stage2 stride         : {metadata.get('stage2_stride', 'N/A')}")
    lines.append(f"Stage3 stride         : {metadata.get('stage3_stride', 'N/A')}")
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
        vq = qr['vuln_func']
        lines.append("-" * 100)
        lines.append(f"[Query {q_idx}/{total_queries}]")
        lines.append(f"  Vuln func           : {vq.get('func_name', '')}")
        lines.append(f"  Vuln origin         : "
                     f"{vq.get('project', '')}/{vq.get('filename', '')}  "
                     f"{vq.get('compiler', '')}-{vq.get('optimizer_level', '')}")
        lines.append(f"  Vuln CVE            : {vq.get('CVE_ID', [])}")
        lines.append(f"  Vuln start_stage    : {vq.get('start_stage', 1)}")
        lines.append(f"  Vuln tokens/blocks  : {qr.get('vuln_size', 0)} / {qr.get('vuln_size2', 0)}")
        lines.append("")

        rankings = qr['rankings']
        lines.append(f"  Full target ranking ({len(rankings)} functions, ties share rank):")
        lines.append(f"    {'rank':<6} {'score':<6} {'stage':<7} {'func':<40} {'label':<10} tokens")
        for r in rankings:
            rank_str = f"{r['rank']}."
            lines.append(
                f"    {rank_str:<6} "
                f"{fmt_score(r['score']):<6} "
                f"{'stage1':<7} "
                f"{r['func_name']:<40} "
                f"{r.get('label', ''):<10} "
                f"{r.get('size', 0)}"
            )
            v_end = qr.get('vuln_size', 0)
            t_end = r.get('size', 0)
            lines.append(
                f"      compared range     : "
                f"vuln=[0:{v_end}] target=[0:{t_end}]"
            )
            lines.append(
                f"      stage scores       : "
                f"stage1={fmt_score(r['score'])}  stage2=-  stage3=-"
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
        lines.append("")
        lines.append("Per-stage execution stats (this target binary):")
        lines.append("  Calls = number of (vuln_query x target_function) pairs that reached the stage.")
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

        model_desc = metadata.get('model_name', 'model')
        descriptions = {'stage1': f'whole function ({model_desc} native embedding)'}

        total_calls = 0
        total_t = 0.0
        for sn in ['stage1']:
            t = stage_times.get(sn)
            c = stage_counts.get(sn, 0)
            if t is None:
                continue
            avg = (t / c) if c else 0.0
            desc = descriptions.get(sn, sn)
            lines.append(
                f"  | {sn:<6} | {desc:<40} "
                f"| {c:>7} | {t:>9.2f} s | {avg:>9.4f} s |"
            )
            total_calls += c
            total_t += t
        lines.append(sep)
        lines.append(
            f"  | Total  | {'':<40} "
            f"| {total_calls:>7} | {total_t:>9.2f} s | {'':>9}   |"
        )

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')


def write_multistage_report(out_path, metadata, query_results):
    """Full Stage1->2->3 cascade report (trex, SAFE) — same section layout as
    vuln_query.py's write_report(), including the flag-based Stage 1 skip
    note, best-window-BB / window-size-stride lines, and per-stage scores.

    Each ranking entry in qr['rankings'] is expected to have:
      func_name, label, size, rank, best_stage, scores (dict stage->score),
      window_meta (dict: best_stage's own meta, see _shared/cascade.py)
    qr also carries: vuln_func, vuln_size, vuln_size2, skip_stage1 (bool)
    """
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
    lines.append(f"Model                 : {metadata.get('model_name', '')}")
    lines.append(f"Stages                : {metadata.get('stages', ['stage1', 'stage2', 'stage3'])}")
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
        vq = qr['vuln_func']
        flag_note = "  (stage 1 skipped — starts from stage 2)" if qr.get('skip_stage1') else ""
        lines.append("-" * 100)
        lines.append(f"[Query {q_idx}/{total_queries}]")
        lines.append(f"  Vuln func           : {vq.get('func_name', '')}")
        lines.append(f"  Vuln origin         : "
                     f"{vq.get('project', '')}/{vq.get('filename', '')}  "
                     f"{vq.get('compiler', '')}-{vq.get('optimizer_level', '')}")
        lines.append(f"  Vuln CVE            : {vq.get('CVE_ID', [])}")
        lines.append(f"  Vuln start_stage    : {vq.get('start_stage', 1)}{flag_note}")
        lines.append(f"  Vuln tokens/blocks  : {qr.get('vuln_size', 0)} / {qr.get('vuln_size2', 0)}")
        lines.append("")

        rankings = qr['rankings']
        s3_stride = metadata.get('stage3_stride', '?')
        lines.append(f"  Full target ranking ({len(rankings)} functions, ties share rank):")
        lines.append(f"    {'rank':<6} {'score':<6} {'stage':<7} {'func':<40} {'label':<10} tokens")
        for r in rankings:
            best_stage = r['best_stage']
            best_score = r['scores'][best_stage]
            rank_str = f"{r['rank']}."
            lines.append(
                f"    {rank_str:<6} "
                f"{fmt_score(best_score):<6} "
                f"{best_stage:<7} "
                f"{r['func_name']:<40} "
                f"{r.get('label', ''):<10} "
                f"{r.get('size', 0)}"
            )

            wm = r.get('window_meta', {})
            v_start, v_end = 0, qr.get('vuln_size', 0)
            t_start, t_end = 0, r.get('size', 0)
            if best_stage == 'stage2':
                bs, be = wm.get('best_window_start', -1), wm.get('best_window_end', -1)
                lines.append(f"      best window BB     : [{bs}:{be}]")
                t_start = wm.get('target_token_start', 0)
                t_end = wm.get('target_token_end', r.get('size', 0))
            elif best_stage == 'stage3':
                ws = wm.get('window_size', 0)
                lines.append(f"      window size/stride : {ws} / {s3_stride}")
                v_end = ws or v_end
                t_start = wm.get('best_target_start', 0)
                t_end = wm.get('best_target_end', 0)

            lines.append(
                f"      compared range     : "
                f"vuln=[{v_start}:{v_end}] target=[{t_start}:{t_end}]"
            )

            scores = r['scores']
            lines.append(
                f"      stage scores       : "
                f"stage1={fmt_score(scores.get('stage1'))}  "
                f"stage2={fmt_score(scores.get('stage2'))}  "
                f"stage3={fmt_score(scores.get('stage3'))}"
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
        model_desc = metadata.get('model_name', 'model')
        descriptions = {
            'stage1': f'whole function ({model_desc} native embedding)',
            'stage2': f'basic-block sliding (stride={s2_stride})',
            'stage3': f'token/instruction sliding (stride={s3_stride})',
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
        total_t = 0.0
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
            total_t += t
        lines.append(sep)
        lines.append(
            f"  | Total  | {'':<40} "
            f"| {total_calls:>7} | {total_t:>9.2f} s | {'':>9}   |"
        )

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')


def write_window_dump(output_path, meta, entries):
    """Same schema as artifact/report.py's
    write_window_dump() -- gzip JSONL, one line per (vuln, target) pair
    that actually reached stage2/stage3, short keys to save space:

    Line 1     : {"meta": true, "source_file": ..., "stage2_stride": ...,
                  "stage3_stride": ...}
    Line 2+    : {"q": vuln_idx, "qf": vuln_func_name, "t": target_idx,
                  "tf": target_func_name, "bs": "stage2"|"stage3",
                  "s2": [[start_bb, end_bb, tok_start, tok_end, score], ...],
                  "s3": [[start_tok, end_tok, score], ...]}

    Only used by models with a real Stage2/3 cascade (trex, SAFE) -- callers
    should skip writing entirely (like BinShot's own `if all_wd_entries:`)
    when entries is empty, rather than emitting a meta-only file.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(output_path, 'wt', encoding='utf-8') as f:
        f.write(json.dumps({'meta': True, **meta}, ensure_ascii=False) + '\n')
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
