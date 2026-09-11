"""Ground-truth per-function labels (Vuln/NVuln/-V/-NV suffixes), sourced from
the corpus labelling pass (see provenance.txt)
rather than recomputed here -- the 6-class scheme depends on DWARF inline-chain
info (`inline` field) that none of our 4 reproduction pipelines' own extractors
(IDA/Ghidra/radare2/trex-tooling) capture themselves. We just look the label up
by (project, filename, compiler, opt, func_name[, start_addr_hex]) from BinShot's
already-labeled per-binary JSON dumps, matched by address when available (same
tool-vs-tool naming-collision problem as vuln db matching, e.g. get_8bit_row_0
vs get_8bit_row_1) and falling back to normalized name otherwise.

Usage:
    import labels as LBL
    label = LBL.get_label('regular', 'binutils-nmnew-20-clang-O1', 'parse_die',
                           start_addr_hex='0x1234')
"""

import json
import re
from pathlib import Path

_ART_ROOT = Path(__file__).resolve().parent.parent.parent

# Targets are always the default builds, for both reference databases, so the
# packaged Ghidra JSONs under artifact/data/targets/ carry every label this
# pipeline looks up. The corpus's -fno-inline Ghidra dumps are not shipped and
# are not needed: nothing here asks for a label in a -fno-inline build.
LABEL_SOURCE_DIRS = {
    'regular': _ART_ROOT / 'data' / 'targets',
    'fno_inline': _ART_ROOT / 'data' / 'targets',
}
_cache = {}


def normalize_func_name(name: str) -> str:
    n = name.strip()
    n = re.sub(r'_(\d+)$', '', n)
    n = re.sub(r'\.(?:isra|constprop|part|cold|llvm)(?:\.\d+)?$', '', n)
    n = re.sub(r'\.clone\.\d+$', '', n)
    n = re.sub(r'\.\d+$', '', n)
    return n


def _load(db: str, binary_name: str):
    key = (db, binary_name)
    if key in _cache:
        return _cache[key]

    by_name, by_norm, by_addr = {}, {}, {}
    path = LABEL_SOURCE_DIRS[db] / f'{binary_name}.json'
    if path.exists():
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            data = []
        for e in data:
            fn = e.get('func_name', '')
            label = e.get('label', '')
            if not fn:
                continue
            by_name[fn] = label
            by_norm.setdefault(normalize_func_name(fn), label)
            addr_hex = e.get('start_addr_hex')
            if addr_hex:
                try:
                    by_addr[int(addr_hex, 16)] = label
                except ValueError:
                    pass

    _cache[key] = (by_name, by_norm, by_addr)
    return _cache[key]


def get_label(db: str, binary_name: str, func_name: str, start_addr_hex=None) -> str:
    """Best-effort ground-truth label lookup. Returns '' if unresolvable
    (binary not in the label source, or function not found there)."""
    by_name, by_norm, by_addr = _load(db, binary_name)

    if start_addr_hex is not None:
        try:
            addr = int(start_addr_hex, 16) if isinstance(start_addr_hex, str) else int(start_addr_hex)
            if addr in by_addr:
                return by_addr[addr]
        except (ValueError, TypeError):
            pass

    if func_name in by_name:
        return by_name[func_name]
    return by_norm.get(normalize_func_name(func_name), '')
