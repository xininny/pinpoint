import torch
from backbone import (
    select_by_containment_count,
    MAX_TOKENS, MIN_TOKENS,
    norm_asm_to_tokens, tokens_to_indices, get_embedding, get_embeddings_batch,
    batch_scores, make_sliding_windows,
)

_MAX_BATCH = 256


def get_cached_window_embeddings(model, vocab, windows, device, cache):
    pending = []
    for start, end, tokens in windows:
        key = (start, end)
        if key in cache:
            continue
        if len(tokens) <= MIN_TOKENS:
            cache[key] = None
            continue
        pending.append((key, tokens_to_indices(tokens, vocab)))

    if pending:
        by_length = {}
        for key, indices in pending:
            by_length.setdefault(len(indices), []).append((key, indices))

        for length, group in by_length.items():
            for i in range(0, len(group), _MAX_BATCH):
                chunk = group[i:i + _MAX_BATCH]
                if len(chunk) == 1:
                    key, indices = chunk[0]
                    cache[key] = get_embedding(model, indices, device)
                else:
                    batch_indices = [indices for _, indices in chunk]
                    batch_embs = get_embeddings_batch(model, batch_indices, device)
                    for (key, _), emb in zip(chunk, batch_embs):
                        cache[key] = emb

    embs = []
    for start, end, tokens in windows:
        key = (start, end)
        if cache.get(key) is not None:
            embs.append(cache[key])
    return embs


def stride1_sliding_compare(model, vocab, vuln_tokens, target_tokens,
                             device, target_cache, stride=1,
                             precomputed_vuln_emb=None):
    empty_result = {
        'max_score': 0.0,
        'best_target_start': 0,
        'best_target_end': 0,
        'window_size': 0,
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

    window_size = min(len(vuln_tokens), MAX_TOKENS)

    target_smaller = len(target_tokens) < window_size

    if precomputed_vuln_emb is not None:
        emb_tensor = precomputed_vuln_emb.get('stage3_emb')
        if emb_tensor is None:
            emb_tensor = precomputed_vuln_emb.get('emb')
        if emb_tensor is None:
            empty_result['status'] = 'vuln_emb_not_found'
            empty_result['window_size'] = window_size
            return empty_result
        vuln_emb = emb_tensor.to(device)
    else:
        vuln_window_tokens = vuln_tokens[:window_size]
        if len(vuln_window_tokens) <= MIN_TOKENS:
            empty_result['status'] = 'vuln_emb_failed'
            empty_result['window_size'] = window_size
            return empty_result
        indices = tokens_to_indices(vuln_window_tokens, vocab)
        vuln_emb = get_embedding(model, indices, device)

    if vuln_emb is None:
        empty_result['status'] = 'vuln_emb_failed'
        empty_result['window_size'] = window_size
        return empty_result

    if target_smaller:
        target_windows = [(0, len(target_tokens), target_tokens)]
    else:
        target_windows = make_sliding_windows(target_tokens, window_size, stride)
    target_embs = get_cached_window_embeddings(model, vocab, target_windows, device, target_cache)

    if not target_embs:
        empty_result['status'] = 'target_emb_failed'
        empty_result['window_size'] = window_size
        return empty_result

    target_embs_matrix = torch.cat(target_embs, dim=0)

    scores = batch_scores(model, vuln_emb, target_embs_matrix)

    all_window_scores = [
        {
            'window_idx': idx,
            'target_start': tw[0],
            'target_end': tw[1],
            'window_score': round(s, 2),
        }
        for idx, (tw, s) in enumerate(zip(target_windows, scores.tolist()))
    ]

    # Token-stride search produces far more ties than Stage 2 -- a long run of
    # windows can all reach the same top score -- so the reported region is the
    # one the containment rule picks among them (token indices at this stage).
    max_score = max(w['window_score'] for w in all_window_scores)
    tied = [w for w in all_window_scores if w['window_score'] == max_score]
    winners, _ = select_by_containment_count(
        [(w['target_start'], w['target_end'], w) for w in tied])
    best = winners[0][2] if winners else tied[0]
    best_target_start = best['target_start']
    best_target_end = best['target_end']

    actual_target_window_size = best_target_end - best_target_start

    return {
        'max_score': round(max_score, 2),
        'best_target_start': best_target_start,
        'best_target_end': best_target_end,
        'window_size': window_size,
        'actual_target_window_size': actual_target_window_size,
        'all_window_scores': all_window_scores,
        'status': 'ok_target_smaller' if target_smaller else 'ok'
    }


def precompute_vuln_stride1_embedding(vuln_func, model, vocab, device):
    vuln_tokens = norm_asm_to_tokens(vuln_func.get('norm_asm', ''))

    if not vuln_tokens or len(vuln_tokens) <= MIN_TOKENS:
        return None

    window_size = min(len(vuln_tokens), MAX_TOKENS)

    vuln_window_tokens = vuln_tokens[:window_size]
    if len(vuln_window_tokens) <= MIN_TOKENS:
        return None

    indices = tokens_to_indices(vuln_window_tokens, vocab)
    emb = get_embedding(model, indices, device)

    if emb is None:
        return None

    return {
        'emb': emb.cpu(),
        'window_size': window_size,
        'token_count': len(vuln_tokens),
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


def run_stage3(vuln_functions, target_func, model, vocab, device,
               filtered_vuln_indices=None, vuln_embeddings=None, stride=1):
    target_tokens = norm_asm_to_tokens(target_func.get('norm_asm', ''))

    if filtered_vuln_indices is None:
        filtered_vuln_indices = list(range(len(vuln_functions)))

    target_cache = {}
    results = []

    for vuln_idx in filtered_vuln_indices:
        vuln_func = vuln_functions[vuln_idx]
        vuln_tokens = norm_asm_to_tokens(vuln_func.get('norm_asm', ''))

        precomp_emb = None
        if vuln_embeddings is not None and vuln_idx in vuln_embeddings:
            precomp_emb = vuln_embeddings[vuln_idx]

        stage3_result = stride1_sliding_compare(
            model, vocab, vuln_tokens, target_tokens,
            device, target_cache, stride=stride,
            precomputed_vuln_emb=precomp_emb
        )

        results.append({
            'vuln_idx': vuln_idx,
            'vuln_func': vuln_func,
            'vuln_tokens': vuln_tokens,
            'score': stage3_result['max_score'],
            'status': stage3_result['status'],
            'best_target_start': stage3_result['best_target_start'],
            'best_target_end': stage3_result['best_target_end'],
            'window_size': stage3_result['window_size'],
            'all_window_scores': stage3_result['all_window_scores'],
        })

    target_cache.clear()
    return results
