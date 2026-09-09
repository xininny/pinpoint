"""Parse vuln_query result TXT files into structured Python data."""
from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable, Iterator, Optional


HEADER_FIELD = re.compile(r'^\s*([A-Za-z][A-Za-z0-9/ ()_-]+?)\s+:\s+(.*)$')
QUERY_TAG = re.compile(r'^\[Query (\d+)/(\d+)\]\s*$')
RANK_ROW = re.compile(
    r'^\s{4}(\d+)\.\s+([0-9.]+|nan)\s+(stage[123]|none)\s+(\S+)\s+'
    r'(NV-V|NV-NV|V-V|V-NV|NV|V)\s+(\d+)\s*$'
)
WINDOW_LINE = re.compile(r'^\s{6}window size/stride\s*:\s*(\d+)\s*/\s*(\d+|\?)\s*$')
BB_WINDOW_LINE = re.compile(r'^\s{6}best window BB\s*:\s*\[(-?\d+):(-?\d+)\]\s*$')
COMPARED_LINE = re.compile(
    r'^\s{6}compared range\s*:\s*vuln=\[(\d+):(\d+)\]\s+target=\[(\d+):(\d+)\]\s*$'
)
STAGE_SCORES = re.compile(
    r'^\s{6}stage scores\s*:\s*stage1=([0-9.\-]+)\s+stage2=([0-9.\-]+)\s+stage3=([0-9.\-]+)\s*$'
)
VULN_FLAG_VAL = re.compile(
    r'^(standalone\(cloning\)|standalone|vuln_inlined)(\s+\(stage 1 skipped[^)]*\))?\s*$'
)
VULN_ORIGIN_VAL = re.compile(r'^(\S+)/(\S+)\s+(\S+)-(\S+)$')
STAGE_STAT_ROW = re.compile(
    r'^\s*\|\s*(stage[123]|Total)\s*\|.*?\|\s*(\d+)\s*\|\s*([0-9.]+)\s*s\s*\|\s*([0-9.]+|\s*)\s*s?\s*\|\s*$'
)


@dataclass
class RankingEntry:
    rank: int
    score: float
    best_stage: str
    func_name: str
    label: str
    tokens: int
    window_size: Optional[int] = None
    best_window_bb: Optional[tuple] = None
    vuln_range: tuple = (0, 0)
    target_range: tuple = (0, 0)
    stage_scores: dict = field(default_factory=dict)


@dataclass
class Query:
    db_kind: str
    target_file: str
    target_project: str
    target_binary: str
    target_compiler: str
    target_opt: str
    target_n_funcs: int
    query_idx: int
    n_queries_in_file: int
    vuln_func: str
    vuln_project: str
    vuln_binary: str
    vuln_compiler: str
    vuln_opt: str
    vuln_cves: list
    vuln_flag: str
    vuln_stage1_skipped: bool
    vuln_tokens: int
    vuln_blocks: int
    rankings: list = field(default_factory=list)


@dataclass
class FileSummary:
    target_file: str
    db_kind: str
    n_queries_processed: int = 0
    total_time_sec: float = 0.0
    avg_time_per_query_sec: float = 0.0
    stage_stats: dict = field(default_factory=dict)


def _parse_float_or_none(s: str) -> Optional[float]:
    s = s.strip()
    if s == '-' or s == '':
        return None
    try:
        v = float(s)
        if v != v:
            return None
        return v
    except ValueError:
        return None


def _parse_score(s: str) -> float:
    s = s.strip()
    if s == 'nan':
        return 0.0
    try:
        return float(s)
    except ValueError:
        return 0.0


def parse_target_filename(name: str) -> tuple:
    base = name.replace('.json', '').replace('.txt', '').replace('result_', '')
    parts = base.split('-')
    if len(parts) >= 5:
        return parts[0], parts[1], parts[-2], parts[-1]
    if len(parts) == 4:
        return parts[0], parts[1], parts[2], parts[3]
    p = parts[0] if parts else ''
    b = parts[1] if len(parts) > 1 else ''
    c = parts[-2] if len(parts) >= 2 else ''
    o = parts[-1] if len(parts) >= 1 else ''
    return p, b, c, o


def _coerce_list(s: str) -> list:
    s = s.strip()
    if not s:
        return []
    try:
        v = ast.literal_eval(s)
        if isinstance(v, (list, tuple)):
            return list(v)
        return [v]
    except (ValueError, SyntaxError):
        return []


class _ParseState:
    HEADER = 'header'
    QUERY_HDR = 'query_header'
    RANKING = 'ranking'
    SUMMARY = 'summary'


def parse_file(path: Path, db_kind: str, warn_cb=None) -> tuple:
    """Parse one TXT and return (queries, summary).

    queries: list[Query]
    summary: FileSummary
    """
    queries: list[Query] = []
    target_file = ''
    target_project = ''
    target_binary = ''
    target_compiler = ''
    target_opt = ''
    target_n_funcs = 0

    summary = FileSummary(target_file=path.name, db_kind=db_kind)

    state = _ParseState.HEADER
    cur_q: Optional[Query] = None
    cur_entry: Optional[RankingEntry] = None
    cur_qhdr_lines = 0

    def warn(msg: str):
        if warn_cb is not None:
            warn_cb(f"{path.name}: {msg}")

    with path.open('r', encoding='utf-8', errors='replace') as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.rstrip('\n')

            # Detect SUMMARY block
            if line.strip() == 'SUMMARY':
                # flush last entry
                cur_entry = None
                state = _ParseState.SUMMARY
                continue

            # Detect query start (any state except summary)
            if state != _ParseState.SUMMARY:
                m = QUERY_TAG.match(line)
                if m:
                    cur_entry = None
                    qi = int(m.group(1))
                    qn = int(m.group(2))
                    cur_q = Query(
                        db_kind=db_kind,
                        target_file=target_file or path.name,
                        target_project=target_project,
                        target_binary=target_binary,
                        target_compiler=target_compiler,
                        target_opt=target_opt,
                        target_n_funcs=target_n_funcs,
                        query_idx=qi,
                        n_queries_in_file=qn,
                        vuln_func='', vuln_project='', vuln_binary='',
                        vuln_compiler='', vuln_opt='',
                        vuln_cves=[], vuln_flag='',
                        vuln_stage1_skipped=False,
                        vuln_tokens=0, vuln_blocks=0,
                        rankings=[],
                    )
                    queries.append(cur_q)
                    state = _ParseState.QUERY_HDR
                    cur_qhdr_lines = 0
                    continue

            if state == _ParseState.HEADER:
                m = HEADER_FIELD.match(line)
                if m:
                    key = m.group(1).strip()
                    val = m.group(2).strip()
                    if key == 'Target file':
                        target_file = val
                        summary.target_file = val
                    elif key == 'Project/Binary':
                        if '/' in val:
                            target_project, target_binary = val.split('/', 1)
                    elif key == 'Compiler/Opt':
                        if '/' in val:
                            target_compiler, target_opt = val.split('/', 1)
                    elif key == 'Target functions':
                        try:
                            target_n_funcs = int(val)
                        except ValueError:
                            target_n_funcs = 0

            elif state == _ParseState.QUERY_HDR and cur_q is not None:
                if line.strip() == '' and cur_qhdr_lines >= 5:
                    continue
                m = HEADER_FIELD.match(line)
                if m:
                    key = m.group(1).strip()
                    val = m.group(2).strip()
                    if key == 'Vuln func':
                        cur_q.vuln_func = val
                        cur_qhdr_lines += 1
                    elif key == 'Vuln origin':
                        om = VULN_ORIGIN_VAL.match(val)
                        if om:
                            cur_q.vuln_project = om.group(1)
                            cur_q.vuln_binary = om.group(2)
                            cur_q.vuln_compiler = om.group(3)
                            cur_q.vuln_opt = om.group(4)
                        cur_qhdr_lines += 1
                    elif key == 'Vuln CVE':
                        cur_q.vuln_cves = _coerce_list(val)
                        cur_qhdr_lines += 1
                    elif key == 'Vuln flag':
                        fm = VULN_FLAG_VAL.match(val)
                        if fm:
                            cur_q.vuln_flag = fm.group(1)
                            cur_q.vuln_stage1_skipped = fm.group(2) is not None
                        else:
                            cur_q.vuln_flag = val.split()[0] if val else ''
                        cur_qhdr_lines += 1
                    elif key == 'Vuln tokens/blocks':
                        try:
                            t, b = val.split('/')
                            cur_q.vuln_tokens = int(t.strip())
                            cur_q.vuln_blocks = int(b.strip())
                        except (ValueError, IndexError):
                            pass
                        cur_qhdr_lines += 1
                # Detect transition to ranking when we see the header row
                if line.lstrip().startswith('rank   score  stage'):
                    state = _ParseState.RANKING
                    cur_entry = None

            elif state == _ParseState.RANKING and cur_q is not None:
                # New ranking entry
                m = RANK_ROW.match(line)
                if m:
                    cur_entry = RankingEntry(
                        rank=int(m.group(1)),
                        score=_parse_score(m.group(2)),
                        best_stage=m.group(3),
                        func_name=m.group(4),
                        label=m.group(5),
                        tokens=int(m.group(6)),
                    )
                    cur_q.rankings.append(cur_entry)
                    continue
                if cur_entry is None:
                    continue
                # Sub-lines for current entry
                m = WINDOW_LINE.match(line)
                if m:
                    try:
                        cur_entry.window_size = int(m.group(1))
                    except ValueError:
                        cur_entry.window_size = None
                    continue
                m = BB_WINDOW_LINE.match(line)
                if m:
                    cur_entry.best_window_bb = (int(m.group(1)), int(m.group(2)))
                    continue
                m = COMPARED_LINE.match(line)
                if m:
                    cur_entry.vuln_range = (int(m.group(1)), int(m.group(2)))
                    cur_entry.target_range = (int(m.group(3)), int(m.group(4)))
                    continue
                m = STAGE_SCORES.match(line)
                if m:
                    cur_entry.stage_scores = {
                        'stage1': _parse_float_or_none(m.group(1)),
                        'stage2': _parse_float_or_none(m.group(2)),
                        'stage3': _parse_float_or_none(m.group(3)),
                    }
                    continue

            elif state == _ParseState.SUMMARY:
                m = HEADER_FIELD.match(line)
                if m:
                    key = m.group(1).strip()
                    val = m.group(2).strip()
                    if key == 'Vuln queries processed':
                        try:
                            summary.n_queries_processed = int(val)
                        except ValueError:
                            pass
                    elif key == 'Total time (sec)':
                        try:
                            summary.total_time_sec = float(val)
                        except ValueError:
                            pass
                    elif key == 'Avg time per query':
                        try:
                            summary.avg_time_per_query_sec = float(val)
                        except ValueError:
                            pass
                m = STAGE_STAT_ROW.match(line)
                if m:
                    sname = m.group(1)
                    try:
                        calls = int(m.group(2))
                        total = float(m.group(3))
                        avg_str = m.group(4).strip()
                        avg = float(avg_str) if avg_str else 0.0
                    except ValueError:
                        continue
                    summary.stage_stats[sname] = {
                        'calls': calls,
                        'total_time_sec': total,
                        'avg_per_call_sec': avg,
                    }

    return queries, summary


def iter_txt_files(db_dir: Path) -> Iterator[Path]:
    """Yield TXT result files, excluding lock files."""
    for p in sorted(db_dir.glob('result_*.txt')):
        if str(p).endswith('.lock'):
            continue
        yield p


def query_to_dict(q: Query) -> dict:
    d = asdict(q)
    d['rankings'] = [asdict(r) for r in q.rankings]
    return d


def summary_to_dict(s: FileSummary) -> dict:
    return asdict(s)
