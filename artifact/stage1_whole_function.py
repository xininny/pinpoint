from backbone import (
    MAX_TOKENS, MIN_TOKENS,
    norm_asm_to_tokens,
    compute_pairwise_similarity, get_single_embedding_truncated,
)


def compare_whole_function(model, vocab, vuln_tokens, target_tokens, target_blocks,
                           device, precomputed_vuln_emb=None):
    result = {
        'score': 0.0,
        'status': 'empty_tokens',
        'vuln_token_count': 0,
        'target_token_count': 0
    }

    if not vuln_tokens or not target_tokens:
        return result

    if len(vuln_tokens) <= MIN_TOKENS:
        result['status'] = 'vuln_too_short'
        return result

    if len(target_tokens) <= MIN_TOKENS:
        result['status'] = 'target_too_short'
        return result

    if precomputed_vuln_emb is not None:
        if isinstance(precomputed_vuln_emb, list):
            vuln_embs = precomputed_vuln_emb
        else:
            vuln_embs = [precomputed_vuln_emb]
    else:
        vuln_blocks_for_chunk = [{'token_start': 0, 'token_end': len(vuln_tokens)}]
        vuln_embs = get_single_embedding_truncated(vuln_blocks_for_chunk, vuln_tokens, model, vocab, device)

    if not vuln_embs:
        result['status'] = 'vuln_emb_failed'
        return result

    if target_blocks:
        target_embs = get_single_embedding_truncated(target_blocks, target_tokens, model, vocab, device)
    else:
        target_blocks_for_chunk = [{'token_start': 0, 'token_end': len(target_tokens)}]
        target_embs = get_single_embedding_truncated(target_blocks_for_chunk, target_tokens, model, vocab, device)

    if not target_embs:
        result['status'] = 'target_emb_failed'
        return result

    score = compute_pairwise_similarity(model, vuln_embs[0], target_embs[0], device)

    return {
        'score': round(score, 2),
        'status': 'ok',
        'vuln_token_count': min(len(vuln_tokens), MAX_TOKENS),
        'target_token_count': min(len(target_tokens), MAX_TOKENS)
    }


def precompute_vuln_embedding(vuln_func, model, vocab, device):
    vuln_tokens = norm_asm_to_tokens(vuln_func.get('norm_asm', ''))
    basic_blocks = vuln_func.get('basic_blocks', [])

    if not basic_blocks:
        basic_blocks = [{'token_start': 0, 'token_end': len(vuln_tokens)}]

    embs = get_single_embedding_truncated(basic_blocks, vuln_tokens, model, vocab, device)

    if not embs:
        return None

    return {
        'emb': embs[0].cpu(),
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


def run_stage1(vuln_functions, target_func, model, vocab, device,
               filtered_vuln_indices=None, vuln_embeddings=None):
    target_tokens = norm_asm_to_tokens(target_func.get('norm_asm', ''))
    target_blocks = target_func.get('basic_blocks', [])

    if filtered_vuln_indices is None:
        filtered_vuln_indices = list(range(len(vuln_functions)))

    results = []

    for vuln_idx in filtered_vuln_indices:
        vuln_func = vuln_functions[vuln_idx]
        vuln_tokens = norm_asm_to_tokens(vuln_func.get('norm_asm', ''))

        precomp_emb = None
        if vuln_embeddings is not None and vuln_idx in vuln_embeddings:
            precomp = vuln_embeddings[vuln_idx]
            precomp_emb = precomp.get('emb')
            if precomp_emb is not None and hasattr(precomp_emb, 'to'):
                precomp_emb = precomp_emb.to(device)

        stage1_result = compare_whole_function(
            model, vocab, vuln_tokens, target_tokens, target_blocks,
            device, precomputed_vuln_emb=precomp_emb
        )

        results.append({
            'vuln_idx': vuln_idx,
            'vuln_func': vuln_func,
            'vuln_tokens': vuln_tokens,
            'score': stage1_result['score'],
            'status': stage1_result['status'],
            'vuln_token_count': len(vuln_tokens),
            'target_token_count': len(target_tokens),
        })

    return results
