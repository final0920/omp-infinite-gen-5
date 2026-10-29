"""Bound already-generated records independently from their display row limit."""
import json


def captured_rows(rows, display_limit, capture_bytes=None):
    if capture_bytes is None:
        return rows[:display_limit]
    if type(capture_bytes) is not int or not 1 <= capture_bytes <= 131072:
        raise ValueError('invalid generated result capture budget')
    selected, used = [], 2
    for row in rows:
        size = len(json.dumps(row, ensure_ascii=False, separators=(',', ':')).encode('utf-8')) + (1 if selected else 0)
        if used + size > capture_bytes:
            break
        selected.append(row)
        used += size
    return selected
