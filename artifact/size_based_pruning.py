ALPHA = 0.540


def _tok_count(norm_asm):
    if not norm_asm:
        return 0
    return norm_asm.count(',') + 1


def pair_passes(target_token_count: int, vuln_token_count: int) -> bool:
    if vuln_token_count <= 0:
        return True
    return target_token_count >= ALPHA * vuln_token_count


def prefilter_vuln_indices(vuln_functions, target_token_count: int,
                           candidate_vuln_indices, stats: dict = None):
    kept = []
    if stats is not None:
        stats.setdefault('candidates', 0)
        stats.setdefault('kept', 0)
        stats.setdefault('skipped', 0)
        stats.setdefault('kept_by_flag', {})
        stats.setdefault('skipped_by_flag', {})

    for idx in candidate_vuln_indices:
        v = vuln_functions[idx]
        vuln_bucket = f"stage{v.get('start_stage', 1)}"
        vuln_tokens = v.get('_ntoks')
        if vuln_tokens is None:
            vuln_tokens = _tok_count(v.get('norm_asm', ''))
            v['_ntoks'] = vuln_tokens

        passed = pair_passes(target_token_count, vuln_tokens)

        if stats is not None:
            stats['candidates'] += 1
            if passed:
                stats['kept'] += 1
                stats['kept_by_flag'][vuln_bucket] = stats['kept_by_flag'].get(vuln_bucket, 0) + 1
            else:
                stats['skipped'] += 1
                stats['skipped_by_flag'][vuln_bucket] = stats['skipped_by_flag'].get(vuln_bucket, 0) + 1

        if passed:
            kept.append(idx)

    return kept


def summarize(stats: dict) -> str:
    if not stats: return 'Filter: (no data)'
    c = stats.get('candidates', 0)
    k = stats.get('kept', 0)
    s = stats.get('skipped', 0)
    if c == 0:
        return 'Filter: 0 candidates'
    return (f'Filter: {s}/{c} skipped ({100*s/c:.1f}%),  {k}/{c} kept ({100*k/c:.1f}%)')


def summarize_by_flag(stats: dict) -> str:
    if not stats: return 'Filter: (no data)'
    lines = ['Filter per-bucket breakdown:']
    all_flags = set(stats.get('kept_by_flag', {})) | set(stats.get('skipped_by_flag', {}))
    for flag in sorted(all_flags):
        k = stats.get('kept_by_flag', {}).get(flag, 0)
        s = stats.get('skipped_by_flag', {}).get(flag, 0)
        tot = k + s
        pct = 100 * s / tot if tot else 0
        lines.append(f'  {flag:<22} α={ALPHA:<5}  '
                     f'skipped={s:>7,}/{tot:<7,} ({pct:5.1f}%)  kept={k:>7,}')
    return '\n'.join(lines)
