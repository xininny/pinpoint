import torch
from backbone import (
    select_by_containment_count,
    MAX_TOKENS, MIN_TOKENS,
    norm_asm_to_tokens, tokens_to_indices, get_embedding, get_embeddings_batch,
    compute_pairwise_similarity, batch_scores, get_single_embedding_truncated,
)

_MAX_BATCH = 256


def _collect_bb_window_tokens(window_bbs, full_tokens, max_tokens=MAX_TOKENS):
    collected = []
    for bb in window_bbs:
        bb_start = bb.get('token_start', 0)
        bb_end = bb.get('token_end', 0)
        bb_tokens = full_tokens[bb_start:bb_end]
        if not bb_tokens:
            continue
        if len(collected) + len(bb_tokens) > max_tokens:
            remaining = max_tokens - len(collected)
            if remaining > 0:
                collected.extend(bb_tokens[:remaining])
            break
        collected.extend(bb_tokens)
    return collected


def _get_cached_bb_window_embeddings(model, vocab, pending_windows, device, cache):
    to_compute = []
    for cache_key, window_bbs, target_tokens in pending_windows:
        if cache_key in cache:
            continue
        collected = _collect_bb_window_tokens(window_bbs, target_tokens)
        if len(collected) <= MIN_TOKENS:
            cache[cache_key] = None
            continue
        to_compute.append((cache_key, tokens_to_indices(collected, vocab)))

    if to_compute:
        by_length = {}
        for cache_key, indices in to_compute:
            by_length.setdefault(len(indices), []).append((cache_key, indices))

        for length, group in by_length.items():
            for i in range(0, len(group), _MAX_BATCH):
                chunk = group[i:i + _MAX_BATCH]
                if len(chunk) == 1:
                    cache_key, indices = chunk[0]
                    cache[cache_key] = get_embedding(model, indices, device)
                else:
                    batch_indices = [indices for _, indices in chunk]
                    batch_embs = get_embeddings_batch(model, batch_indices, device)
                    for (cache_key, _), emb in zip(chunk, batch_embs):
                        cache[cache_key] = emb


def compute_included_bb_count(basic_blocks, full_tokens, max_tokens=MAX_TOKENS):
    if not basic_blocks:
        return 1

    total_tokens = 0
    included_count = 0

    for bb in basic_blocks:
        bb_start = bb.get('token_start', 0)
        bb_end = bb.get('token_end', 0)
        bb_tokens = full_tokens[bb_start:bb_end]

        if not bb_tokens:
            continue

        if total_tokens + len(bb_tokens) > max_tokens:
            if total_tokens < max_tokens:
                included_count += 1
            break

        total_tokens += len(bb_tokens)
        included_count += 1

    return max(included_count, 1)


def resolve_window_bb_count(vuln_blocks, vuln_tokens, vuln_included_bb_count=None):
    if vuln_included_bb_count is not None:
        return max(vuln_included_bb_count, 1)
    return compute_included_bb_count(vuln_blocks, vuln_tokens) if vuln_blocks else 1


def compute_window_start_range(num_target_blocks, window_bb_count, stride):
    if num_target_blocks <= 0 or stride <= 0:
        return []

    if num_target_blocks <= window_bb_count:
        return [0]

    max_window_start = num_target_blocks - window_bb_count
    starts = list(range(0, max_window_start + 1, stride))
    if starts[-1] != max_window_start:
        starts.append(max_window_start)
    return starts


def basicblock_sliding_compare(model, vocab, vuln_blocks, target_blocks,
                                target_tokens, vuln_tokens, device, target_cache,
                                precomputed_vuln_emb=None, vuln_included_bb_count=None,
                                stride=1):
    empty_result = {
        'max_score': 0.0,
        'best_window_start': -1,
        'best_window_end': -1,
        'best_target_token_start': 0,
        'best_target_token_end': 0,
        'all_window_scores': [],
        'status': 'empty'
    }

    if not vuln_tokens or not target_tokens:
        empty_result['status'] = 'empty_tokens'
        return empty_result

    if len(vuln_tokens) <= MIN_TOKENS:
        empty_result['status'] = 'vuln_too_short'
        return empty_result

    if len(target_tokens) <= MIN_TOKENS:
        empty_result['status'] = 'target_too_short'
        return empty_result

    if not target_blocks:
        empty_result['status'] = 'empty_target_blocks'
        return empty_result

    n = len(target_blocks)

    if n == 0:
        empty_result['status'] = 'target_no_blocks'
        return empty_result

    if stride <= 0:
        empty_result['status'] = 'invalid_stride'
        return empty_result

    k = resolve_window_bb_count(vuln_blocks, vuln_tokens, vuln_included_bb_count)
    window_starts = compute_window_start_range(n, k, stride)

    if precomputed_vuln_emb is not None:
        if isinstance(precomputed_vuln_emb, list):
            vuln_embs = precomputed_vuln_emb
        else:
            vuln_embs = [precomputed_vuln_emb]
    else:
        if not vuln_blocks:
            vuln_blocks_for_chunk = [{'token_start': 0, 'token_end': len(vuln_tokens)}]
        else:
            vuln_blocks_for_chunk = vuln_blocks
        vuln_embs = get_single_embedding_truncated(vuln_blocks_for_chunk, vuln_tokens, model, vocab, device)

    if not vuln_embs:
        empty_result['status'] = 'vuln_emb_failed'
        return empty_result

    window_meta = []
    for i in window_starts:
        window_bbs = target_blocks[i:i + k]
        window_start_bb = i
        window_end_bb = min(i + k - 1, n - 1)
        token_start = window_bbs[0].get('token_start', 0)
        token_end = window_bbs[-1].get('token_end', len(target_tokens))
        window_tokens = target_tokens[token_start:token_end]
        if len(window_tokens) <= MIN_TOKENS:
            continue
        window_meta.append((i, window_bbs, window_start_bb, window_end_bb, token_start, token_end, window_tokens))

    if not window_meta:
        empty_result['status'] = 'no_valid_windows'
        return empty_result

    pending = [(('window_emb', wt[4], wt[5]), wt[1], target_tokens) for wt in window_meta]
    _get_cached_bb_window_embeddings(model, vocab, pending, device, target_cache)

    kept_meta = []
    kept_embs = []
    for wt in window_meta:
        cache_key = ('window_emb', wt[4], wt[5])
        emb = target_cache.get(cache_key)
        if emb is None:
            continue
        kept_meta.append(wt)
        kept_embs.append(emb)

    if not kept_meta:
        empty_result['status'] = 'no_valid_windows'
        return empty_result

    target_embs_matrix = torch.cat(kept_embs, dim=0)
    scores = batch_scores(model, vuln_embs[0], target_embs_matrix).tolist()

    all_window_scores = []
    for (i, window_bbs, window_start_bb, window_end_bb, token_start, token_end, window_tokens), score \
            in zip(kept_meta, scores):
        all_window_scores.append({
            'window_idx': i,
            'window_start_bb': window_start_bb,
            'window_end_bb': window_end_bb,
            'target_token_start': token_start,
            'target_token_end': token_end,
            'window_token_count': len(window_tokens),
            'window_score': round(score, 2)
        })

    if not all_window_scores:
        empty_result['status'] = 'no_valid_windows'
        return empty_result

    # Several windows routinely tie at the top score, so the score alone does not
    # identify the reported region; the containment rule breaks the tie by window
    # position (basic-block indices at this stage).
    max_score = max(w['window_score'] for w in all_window_scores)
    tied = [w for w in all_window_scores if w['window_score'] == max_score]
    winners, _ = select_by_containment_count(
        [(w['window_start_bb'], w['window_end_bb'], w) for w in tied])
    best_window = winners[0][2] if winners else tied[0]

    return {
        'max_score': round(max_score, 2),
        'best_window_start': best_window['window_start_bb'],
        'best_window_end': best_window['window_end_bb'],
        'best_target_token_start': best_window['target_token_start'],
        'best_target_token_end': best_window['target_token_end'],
        'all_window_scores': all_window_scores,
        'status': 'ok'
    }


def precompute_vuln_bb_embedding(vuln_func, model, vocab, device):
    vuln_tokens = norm_asm_to_tokens(vuln_func.get('norm_asm', ''))
    basic_blocks = vuln_func.get('basic_blocks', [])

    if not basic_blocks:
        basic_blocks = [{'token_start': 0, 'token_end': len(vuln_tokens)}]

    embs = get_single_embedding_truncated(basic_blocks, vuln_tokens, model, vocab, device)
    included_bb_count = compute_included_bb_count(basic_blocks, vuln_tokens)

    if not embs:
        return None

    return {
        'emb': embs[0].cpu(),
        'num_blocks': included_bb_count,
        'original_num_blocks': len(basic_blocks),
        'token_count': min(len(vuln_tokens), MAX_TOKENS),
        'original_token_count': len(vuln_tokens),
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


def run_stage2(vuln_functions, target_func, model, vocab, device,
               filtered_vuln_indices=None, vuln_embeddings=None, stride=1):
    target_tokens = norm_asm_to_tokens(target_func.get('norm_asm', ''))
    target_blocks = target_func.get('basic_blocks', [])

    if filtered_vuln_indices is None:
        filtered_vuln_indices = list(range(len(vuln_functions)))

    target_cache = {}
    results = []

    for vuln_idx in filtered_vuln_indices:
        vuln_func = vuln_functions[vuln_idx]
        vuln_tokens = norm_asm_to_tokens(vuln_func.get('norm_asm', ''))
        vuln_blocks = vuln_func.get('basic_blocks', [])

        precomp_emb = None
        vuln_included_bb_count = None
        if vuln_embeddings is not None and vuln_idx in vuln_embeddings:
            precomp = vuln_embeddings[vuln_idx]
            precomp_emb = precomp.get('emb')
            if precomp_emb is not None and hasattr(precomp_emb, 'to'):
                precomp_emb = precomp_emb.to(device)
            vuln_included_bb_count = precomp.get('num_blocks')

        stage2_result = basicblock_sliding_compare(
            model, vocab, vuln_blocks, target_blocks,
            target_tokens, vuln_tokens, device, target_cache,
            precomputed_vuln_emb=precomp_emb,
            vuln_included_bb_count=vuln_included_bb_count,
            stride=stride
        )

        results.append({
            'vuln_idx': vuln_idx,
            'vuln_func': vuln_func,
            'vuln_tokens': vuln_tokens,
            'vuln_blocks': vuln_blocks,
            'score': stage2_result['max_score'],
            'status': stage2_result['status'],
            'best_window_start': stage2_result['best_window_start'],
            'best_window_end': stage2_result['best_window_end'],
            'best_target_token_start': stage2_result['best_target_token_start'],
            'best_target_token_end': stage2_result['best_target_token_end'],
            'all_window_scores': stage2_result['all_window_scores'],
        })

    target_cache.clear()
    return results
