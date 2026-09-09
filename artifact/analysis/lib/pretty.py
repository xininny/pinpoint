"""Markdown table renderer and small formatting helpers."""
from __future__ import annotations


def fmt_pct(x, digits=1):
    if x is None:
        return 'N/A'
    return f'{x*100:.{digits}f}%'


def fmt_num(x, digits=3):
    if x is None:
        return 'N/A'
    if isinstance(x, int):
        return f'{x}'
    try:
        return f'{x:.{digits}f}'
    except Exception:
        return str(x)


def render_table(headers: list, rows: list, align: list = None) -> str:
    """Render markdown table.

    headers: list of column header strings
    rows: list of list of stringifiable cells
    align: list of 'l'/'c'/'r' per column (default: left)
    """
    n = len(headers)
    align = align or ['l'] * n

    def sep(a):
        if a == 'l':
            return ':---'
        if a == 'r':
            return '---:'
        if a == 'c':
            return ':---:'
        return '---'

    def stringify(cell):
        if cell is None:
            return 'N/A'
        if isinstance(cell, float):
            return fmt_num(cell)
        return str(cell)

    lines = []
    lines.append('| ' + ' | '.join(headers) + ' |')
    lines.append('|' + '|'.join(sep(a) for a in align) + '|')
    for row in rows:
        cells = [stringify(c) for c in row]
        while len(cells) < n:
            cells.append('N/A')
        lines.append('| ' + ' | '.join(cells) + ' |')
    return '\n'.join(lines)


def render_kv(items: list) -> str:
    """Render a 2-column key-value table."""
    return render_table(['항목', '값'], items)
