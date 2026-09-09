import bisect
import os
import sys
import json
import torch

_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_REPO_ROOT, 'binshot'))

from voca import WordVocab
from binshot import SimilarityModel
import hparams as hp

MAX_TOKENS = hp.enc_maxlen - 3
MIN_TOKENS = 0


def load_model(sim_model_path, vocab_path, device):
    import __main__
    if not hasattr(__main__, 'WordVocab'):
        __main__.WordVocab = WordVocab
    if not hasattr(__main__, 'SimilarityModel'):
        __main__.SimilarityModel = SimilarityModel

    print(f"[+] Loading vocabulary from {vocab_path}")
    vocab = WordVocab.load_vocab(vocab_path)
    print(f"[+] Loaded {vocab.vocab_size} vocas")

    print(f"[+] Loading similarity model from {sim_model_path}")
    model = torch.load(sim_model_path, map_location=device, weights_only=False)
    model.eval()
    model.to(device)

    return model, vocab


def norm_asm_to_tokens(norm_asm):
    if not norm_asm:
        return []
    return norm_asm.replace(" ", "_").split(',')


def tokens_to_indices(tokens, vocab, max_tokens=MAX_TOKENS):
    tokens = tokens[:max_tokens]
    indices = [vocab.voca_idx(token) for token in tokens]
    indices = [vocab.sos_index] + indices + [vocab.eos_index]
    max_total = hp.enc_maxlen - 1
    if len(indices) > max_total:
        indices = indices[:max_total]
    return indices


def get_embedding(model, indices, device):
    seq_len = len(indices)
    position = list(range(1, seq_len + 1))
    input_tensor = torch.tensor([indices]).long().to(device)
    position_tensor = torch.tensor([position]).long().to(device)
    with torch.no_grad():
        x, _, _ = model.bert(input_tensor, position_tensor)
    return x[:, 0, :]


def get_embeddings_batch(model, indices_list, device):
    lengths = {len(idx) for idx in indices_list}
    if len(lengths) != 1:
        raise ValueError(
            f"get_embeddings_batch requires equal-length sequences, got lengths={sorted(lengths)}"
        )
    seq_len = lengths.pop()
    position = list(range(1, seq_len + 1))
    input_tensor = torch.tensor(indices_list).long().to(device)
    position_tensor = torch.tensor([position] * len(indices_list)).long().to(device)
    with torch.no_grad():
        x, _, _ = model.bert(input_tensor, position_tensor)
    return [x[i:i + 1, 0, :] for i in range(x.size(0))]


def compute_pairwise_similarity(model, emb1, emb2, device):
    with torch.no_grad():
        emb1 = emb1.to(device)
        emb2 = emb2.to(device)
        diff = (emb1 - emb2) ** 2
        output = model.linear(diff)
        score = torch.sigmoid(output).item()
    return score


def batch_scores(model, source_emb, target_embs_matrix):
    with torch.no_grad():
        N = target_embs_matrix.shape[0]
        source_exp = source_emb.expand(N, -1)
        diff = (source_exp - target_embs_matrix) ** 2
        output = model.linear(diff)
        scores = torch.sigmoid(output).squeeze(1)
    return scores


def get_tokens_embedding(tokens, model, vocab, device, max_tokens=MAX_TOKENS):
    if not tokens or len(tokens) <= MIN_TOKENS:
        return None

    indices = tokens_to_indices(tokens[:max_tokens], vocab)
    return get_embedding(model, indices, device)


def _attach_bb_token_offsets(funcs):
    for fn in funcs:
        cursor = 0
        for bb in fn.get('basic_blocks', []) or []:
            norm = bb.get('norm_asm') or ''
            n = len([t for t in norm.split(',') if t]) if norm else 0
            bb['token_start'] = cursor
            bb['token_end'] = cursor + n
            cursor += n


def load_vuln_functions(vuln_path):
    print(f"[+] Loading vulnerable functions from {vuln_path}")
    with open(vuln_path, 'r') as f:
        vuln_functions = json.load(f)
    _attach_bb_token_offsets(vuln_functions)
    print(f"[+] Loaded {len(vuln_functions)} vulnerable functions")
    return vuln_functions


def load_target_functions(json_file):
    with open(json_file, 'r') as f:
        funcs = json.load(f)
    _attach_bb_token_offsets(funcs)
    return funcs


def filter_vuln_indices_by_project_binary(vuln_functions, project, binary):
    return [
        idx for idx, v in enumerate(vuln_functions)
        if v.get('project', '') == project and v.get('filename', '') == binary
    ]


def parse_target_filename(file_name):
    parts = file_name.replace('.json', '').split('-')
    project = parts[0] if len(parts) > 0 else ''
    binary = parts[1] if len(parts) > 1 else ''
    compiler = parts[2] if len(parts) > 2 else ''
    opt = parts[3] if len(parts) > 3 else ''
    return project, binary, compiler, opt


def fmt_score(score):
    if score is None:
        return None
    return round(score, 2)


def make_sliding_windows(tokens, window_size, stride):
    n = len(tokens)
    if n <= window_size:
        return [(0, n, tokens)]

    last_start = n - window_size
    starts = list(range(0, last_start + 1, stride))
    if starts[-1] != last_start:
        starts.append(last_start)

    windows = []
    for start in starts:
        end = start + window_size
        windows.append((start, end, tokens[start:end]))
    return windows


def get_single_embedding_truncated(window_bbs, full_tokens, model, vocab, device, max_tokens=MAX_TOKENS):
    if not window_bbs or not full_tokens:
        return []

    collected_tokens = []

    for bb in window_bbs:
        bb_start = bb.get('token_start', 0)
        bb_end = bb.get('token_end', 0)
        bb_tokens = full_tokens[bb_start:bb_end]

        if not bb_tokens:
            continue

        if len(collected_tokens) + len(bb_tokens) > max_tokens:
            remaining = max_tokens - len(collected_tokens)
            if remaining > 0:
                collected_tokens.extend(bb_tokens[:remaining])
            break

        collected_tokens.extend(bb_tokens)

    if len(collected_tokens) <= MIN_TOKENS:
        return []

    indices = tokens_to_indices(collected_tokens, vocab)
    emb = get_embedding(model, indices, device)

    return [emb]


def get_truncated_tokens_by_bb(window_bbs, full_tokens, max_tokens=MAX_TOKENS, start_bb_idx=0):
    if not window_bbs or not full_tokens:
        return []

    result = []
    total_collected = 0

    for bb_i, bb in enumerate(window_bbs):
        actual_bb_idx = start_bb_idx + bb_i
        bb_start = bb.get('token_start', 0)
        bb_end = bb.get('token_end', 0)
        bb_tokens = full_tokens[bb_start:bb_end]

        if not bb_tokens:
            continue

        if total_collected >= max_tokens:
            break

        if total_collected + len(bb_tokens) > max_tokens:
            remaining = max_tokens - total_collected
            if remaining > 0:
                result.append({
                    'bb_idx': actual_bb_idx,
                    'tokens': ','.join(bb_tokens[:remaining]),
                    'token_count': remaining,
                    'truncated': True
                })
                total_collected += remaining
            break

        result.append({
            'bb_idx': actual_bb_idx,
            'tokens': ','.join(bb_tokens),
            'token_count': len(bb_tokens),
            'truncated': False
        })
        total_collected += len(bb_tokens)

    return result


def select_by_containment_count(windows):
    """Paper Section VII-A, equations (1) and (2).

    Among the windows that attain the maximum similarity score, the score alone
    cannot say which one holds the vulnerable code. Each such window w is scored
    instead by how many of the other maximum-score windows start inside it:

        c(w) = |{ w' in W_max : s(w) <= s(w') <= e(w) }|

    and the window(s) with the largest count are reported. s(.) and e(.) are the
    indices of the first and last elements the window covers -- basic blocks at
    Stage 2, tokens at Stage 3. The rule uses only scores and window positions,
    never the ground truth.

    `windows` is a list of (start, end, ...) tuples. Returns (winners, count).
    """
    if not windows:
        return [], 0
    starts = sorted(w[0] for w in windows)
    counts = []
    for w in windows:
        lo, hi = w[0], w[1]
        counts.append(bisect.bisect_right(starts, hi) - bisect.bisect_left(starts, lo))
    best = max(counts)
    return [w for w, c in zip(windows, counts) if c == best], best
