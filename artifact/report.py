import gzip
import json

from backbone import fmt_score


def write_jsonl_metadata(output_path, metadata):
    metadata['type'] = 'metadata'
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(json.dumps(metadata, ensure_ascii=False) + '\n')


def write_jsonl_result(output_path, result_entry):
    result_entry['type'] = 'result'
    with open(output_path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(result_entry, ensure_ascii=False) + '\n')


def write_jsonl_completion(output_path, processed_count, status='completed',
                            total_time=None):
    completion = {
        'type': 'completion',
        'status': status,
        'processed_functions': processed_count,
    }
    if total_time is not None:
        completion['total_time_sec'] = round(total_time, 2)
        if processed_count > 0:
            completion['avg_time_per_func'] = round(total_time / processed_count, 4)
    with open(output_path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(completion, ensure_ascii=False) + '\n')


def parse_jsonl(jsonl_path):
    metadata = {}
    results = []

    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                obj_type = obj.get('type', '')

                if obj_type == 'metadata':
                    metadata = obj
                elif obj_type == 'result':
                    results.append(obj)
                elif obj_type == 'completion':
                    metadata['status'] = obj.get('status', 'completed')
                    metadata['processed_functions'] = obj.get('processed_functions', len(results))
                    if 'total_time_sec' in obj:
                        metadata['total_time_sec'] = obj['total_time_sec']
                    if 'avg_time_per_func' in obj:
                        metadata['avg_time_per_func'] = obj['avg_time_per_func']
            except json.JSONDecodeError:
                continue

    return metadata, results


def write_txt_report(output_txt_path, jsonl_path):
    metadata, results = parse_jsonl(jsonl_path)
    return write_txt_report_direct(output_txt_path, metadata, results)


def write_txt_report_direct(output_txt_path, metadata, results):
    lines = []
    lines.append("=" * 100)
    lines.append("ASM Similarity Report (Stage 1/2/3)")
    lines.append("=" * 100)
    lines.append(f"Source file           : {metadata.get('source_file', '')}")
    lines.append(f"Project/Binary        : {metadata.get('project', '')}/{metadata.get('binary', '')}")
    lines.append(f"Compiler/Opt          : {metadata.get('compiler', '')}/{metadata.get('optimizer_level', '')}")
    lines.append(f"Total functions       : {metadata.get('total_functions', 0)}")
    lines.append(f"Processed functions   : {metadata.get('processed_functions', len(results))}")
    lines.append(f"Filtered vuln count   : {metadata.get('filtered_vuln_count', 0)}")
    lines.append(f"Mode                  : {metadata.get('mode', 'stages')}")
    lines.append(f"Stages                : {metadata.get('stages', [])}")
    if metadata.get('scoring'):
        lines.append(f"Scoring               : {metadata.get('scoring')}")
    if metadata.get('scoring_formula'):
        lines.append(f"Scoring formula       : {metadata.get('scoring_formula')}")
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
    elif metadata.get('filter_enabled') is False:
        lines.append(f"Filter                : disabled")
    lines.append("")

    for entry in results:
        target_func_name = entry.get('func_name', '')

        lines.append("-" * 100)
        lines.append(f"Input order #{entry.get('input_order', 0)} | target_idx={entry.get('target_idx', -1)}")
        lines.append(f"Target function       : {target_func_name}")
        lines.append(f"Label                 : {entry.get('label', '')}")
        lines.append(f"Target tokens/blocks  : {entry.get('target_token_count', 0)} / {entry.get('target_block_count', 0)}")
        lines.append(f"Comparison status     : {entry.get('comparison_status', '')}")

        all_matches = entry.get('all_matches', [])
        lines.append(f"Compared vuln count   : {len(all_matches)}")

        best_match = entry.get('best_match')
        if best_match:
            lines.append(f"Top 1 final score     : {best_match.get('final_score')} (stage: {best_match.get('match_stage', 'N/A')})")
        else:
            lines.append("Top 1 final score     : None")

        if all_matches:
            lines.append("All vuln matches (sorted by final_score desc):")
            for m in all_matches:
                lines.append(f"  [{m.get('rank', 0)}]")
                lines.append(f"    vuln func         : {m.get('vuln_func_name', '')}")
                lines.append(f"    project/file      : {m.get('vuln_project', '')}/{m.get('vuln_filename', '')}")
                lines.append(f"    compiler/opt      : {m.get('vuln_compiler', '')}/{m.get('vuln_optimizer_level', '')}")
                lines.append(f"    cve_id            : {m.get('cve_id', [])}")
                lines.append(f"    vuln tokens/blocks: {m.get('vuln_token_count', 0)} / {m.get('vuln_block_count', 0)}")

                for sn in ['stage1', 'stage2', 'stage3']:
                    if m.get(f'{sn}_asm_score') is not None:
                        asm_s = m.get(f'{sn}_asm_score')
                        desc_s = m.get(f'{sn}_desc_score')
                        final_s = m.get(f'{sn}_final_score')
                        lines.append(f"    {sn} score        : {asm_s} / {desc_s} / {final_s}")
                    elif m.get(f'{sn}_score') is not None:
                        lines.append(f"    {sn} score        : {m.get(f'{sn}_score')}")

                lines.append(f"    final score       : {m.get('final_score')} ({m.get('match_stage', 'N/A')})")
                lines.append(f"    block mode (v/t)  : {m.get('vuln_block_mode', 'N/A')} / {m.get('target_block_mode', 'N/A')}")

                if m.get('match_stage') == 'stage1':
                    lines.append(f"    target token range: 0 ~ {m.get('best_target_token_end', 0)}")
                elif m.get('match_stage') == 'stage2':
                    lines.append(f"    best window BB    : {m.get('best_window_start_bb', -1)} ~ {m.get('best_window_end_bb', -1)}")
                    lines.append(f"    target token range: {m.get('best_target_token_start', 0)} ~ {m.get('best_target_token_end', 0)}")
                elif m.get('match_stage') == 'stage3':
                    lines.append(f"    window size/stride: {m.get('window_size', 0)} / {m.get('stride', '?')}")
                    lines.append(f"    best vuln window  : {m.get('best_vuln_window_start', 0)} ~ {m.get('best_vuln_window_end', 0)}")
                    lines.append(f"    best target window: {m.get('best_target_window_start', 0)} ~ {m.get('best_target_window_end', 0)}")

                if m.get('comparison_status') and m.get('comparison_status') != 'ok':
                    lines.append(f"    status            : {m.get('comparison_status')}")

                vuln_tokens = m.get('vuln_compared_tokens', '')
                target_tokens = m.get('target_compared_tokens', '')

                if vuln_tokens or target_tokens:
                    lines.append(f"    --- Compared Tokens ---")
                    if vuln_tokens:
                        token_count = len(vuln_tokens.split(',')) if vuln_tokens else 0
                        lines.append(f"    [Vuln] ({token_count} tokens):")
                        lines.append(f"      {vuln_tokens[:200]}{'...' if len(vuln_tokens) > 200 else ''}")
                    if target_tokens:
                        token_count = len(target_tokens.split(',')) if target_tokens else 0
                        lines.append(f"    [Target] ({token_count} tokens):")
                        lines.append(f"      {target_tokens[:200]}{'...' if len(target_tokens) > 200 else ''}")

                vuln_desc = m.get('vuln_description', '')
                target_desc = m.get('target_description', '')

                if vuln_desc or target_desc:
                    lines.append(f"    --- Descriptions ---")
                    if vuln_desc:
                        lines.append(f"    [Vuln Desc]:")
                        lines.append(f"      {vuln_desc[:300]}{'...' if len(vuln_desc) > 300 else ''}")
                    if target_desc:
                        lines.append(f"    [Target Desc]:")
                        lines.append(f"      {target_desc[:300]}{'...' if len(target_desc) > 300 else ''}")

                lines.append("")

    lines.append("=" * 100)
    lines.append("SUMMARY")
    lines.append("=" * 100)
    processed_count = metadata.get('processed_functions', len(results))
    total_time = metadata.get('total_time_sec')
    avg_time = metadata.get('avg_time_per_func')

    lines.append(f"Processed functions   : {processed_count}")
    if total_time is not None:
        lines.append(f"Total time (sec)      : {total_time:.2f}")
        if avg_time is not None:
            lines.append(f"Avg time per func     : {avg_time:.4f}")
        elif processed_count > 0:
            lines.append(f"Avg time per func     : {total_time / processed_count:.4f}")

    stage_times_sec = metadata.get('stage_times_sec') or {}
    stage_counts = metadata.get('stage_counts') or {}
    if stage_times_sec:
        for sn in ['stage1', 'stage2', 'stage3']:
            t = stage_times_sec.get(sn)
            c = stage_counts.get(sn, 0)
            if t is None:
                continue
            avg = (t / c) if c else 0.0
            lines.append(f"{sn} time (sec)      : {t:.2f}  (calls={c}, avg={avg:.4f})")
    lines.append("")

    label_stats = {}
    for entry in results:
        label = entry.get('label', 'Unknown')
        if label not in label_stats:
            label_stats[label] = {
                'total': 0,
                'ge_099': 0,
                'ge_095': 0,
                'ge_090': 0,
            }
        label_stats[label]['total'] += 1

        top1_score = entry.get('top1_final_score')
        if top1_score is None:
            all_matches = entry.get('all_matches', [])
            if all_matches:
                top1_score = all_matches[0].get('final_score', 0)

        if top1_score is not None:
            if top1_score >= 0.99:
                label_stats[label]['ge_099'] += 1
            if top1_score >= 0.95:
                label_stats[label]['ge_095'] += 1
            if top1_score >= 0.90:
                label_stats[label]['ge_090'] += 1

    with open(output_txt_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines) + "\n")

    return True


def create_result_entry(target_idx, target_func, target_tokens, target_blocks,
                        comparison_status, best_vuln_match, all_vuln_matches, elapsed_time):
    return {
        'target_idx': target_idx,
        'input_order': target_idx + 1,
        'func_name': target_func.get('func_name', ''),
        'target_token_count': len(target_tokens),
        'target_block_count': len(target_blocks),
        'label': target_func.get('label', ''),
        'time_sec': round(elapsed_time, 4),
        'comparison_status': comparison_status,
        'best_match': best_vuln_match,
        'all_matches': all_vuln_matches
    }


def create_match_entry(vuln_idx, vuln_func, vuln_tokens, vuln_blocks,
                       final_score, stage_scores, match_stage, comparison_status):
    entry = {
        'vuln_idx': vuln_idx,
        'vuln_project': vuln_func.get('project', ''),
        'vuln_filename': vuln_func.get('filename', ''),
        'vuln_func_name': vuln_func.get('func_name', ''),
        'vuln_compiler': vuln_func.get('compiler', ''),
        'vuln_optimizer_level': vuln_func.get('optimizer_level', ''),
        'vuln_token_count': len(vuln_tokens),
        'vuln_block_count': len(vuln_blocks) if vuln_blocks else 0,
        'cve_id': vuln_func.get('CVE_ID', []),
        'final_score': fmt_score(final_score),
        'match_stage': match_stage,
        'comparison_status': comparison_status,
    }

    for stage, score in stage_scores.items():
        entry[f'{stage}_score'] = fmt_score(score)

    return entry


def create_metadata(file_name, file_project, file_binary, file_compiler, file_opt,
                    total_functions, filtered_vuln_count, mode='stages', stages=None):
    return {
        'source_file': file_name,
        'project': file_project,
        'binary': file_binary,
        'compiler': file_compiler,
        'optimizer_level': file_opt,
        'total_functions': total_functions,
        'filtered_vuln_count': filtered_vuln_count,
        'mode': mode,
        'stages': stages or [],
    }


def write_window_dump(output_path, meta, entries):
    with gzip.open(output_path, 'wt', encoding='utf-8') as f:
        f.write(json.dumps({'meta': True, **meta}, ensure_ascii=False) + '\n')
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
