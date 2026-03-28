"""Comparer — diff two responses with multiple diff modes."""

from __future__ import annotations

import difflib
import json
import re

from models import CompareRequest, DiffResult
from state import state


def _flow_to_text(flow_id: str) -> str:
    """Convert a flow's response to text for comparison."""
    flow = state.get_flow(flow_id)
    if not flow:
        return f"[Flow {flow_id} not found]"
    if not flow.response:
        return f"[Flow {flow_id} has no response]"

    lines = [f"HTTP {flow.response.status_code} {flow.response.reason}"]
    for k, v in flow.response.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if flow.response.body:
        lines.append(flow.response.body)
    return "\n".join(lines)


def _word_diff(left: str, right: str) -> str:
    """Word-level diff — shows differences at the word level."""
    left_words = re.findall(r'\S+|\s+', left)
    right_words = re.findall(r'\S+|\s+', right)

    sm = difflib.SequenceMatcher(None, left_words, right_words)
    output = []

    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == 'equal':
            output.append("".join(left_words[i1:i2]))
        elif op == 'delete':
            output.append(f"[-{''.join(left_words[i1:i2])}-]")
        elif op == 'insert':
            output.append(f"[+{''.join(right_words[j1:j2])}+]")
        elif op == 'replace':
            output.append(f"[-{''.join(left_words[i1:i2])}-]")
            output.append(f"[+{''.join(right_words[j1:j2])}+]")

    return "".join(output)


def _char_diff(left: str, right: str) -> str:
    """Character-level diff."""
    sm = difflib.SequenceMatcher(None, left, right)
    output = []

    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == 'equal':
            output.append(left[i1:i2])
        elif op == 'delete':
            output.append(f"[-{left[i1:i2]}-]")
        elif op == 'insert':
            output.append(f"[+{right[j1:j2]}+]")
        elif op == 'replace':
            output.append(f"[-{left[i1:i2]}-][+{right[j1:j2]}+]")

    return "".join(output)


def _json_diff(left: str, right: str) -> str:
    """JSON-aware diff — pretty-prints both sides before diffing."""
    try:
        left_json = json.dumps(json.loads(left), indent=2, sort_keys=True)
    except (json.JSONDecodeError, TypeError):
        left_json = left

    try:
        right_json = json.dumps(json.loads(right), indent=2, sort_keys=True)
    except (json.JSONDecodeError, TypeError):
        right_json = right

    left_lines = left_json.splitlines(keepends=True)
    right_lines = right_json.splitlines(keepends=True)

    diff = list(difflib.unified_diff(
        left_lines, right_lines,
        fromfile="left", tofile="right",
        lineterm="",
    ))
    return "\n".join(diff)


def _html_structural_diff(left: str, right: str) -> str:
    """DOM tree structural comparison — compares HTML tag structure."""
    from html.parser import HTMLParser

    class TagExtractor(HTMLParser):
        def __init__(self):
            super().__init__()
            self.tags: list[str] = []
            self._depth = 0

        def handle_starttag(self, tag, attrs):
            indent = "  " * self._depth
            attr_str = " ".join(f'{k}="{v}"' for k, v in attrs if k in ("id", "class", "name", "type"))
            self.tags.append(f"{indent}<{tag}{' ' + attr_str if attr_str else ''}>")
            self._depth += 1

        def handle_endtag(self, tag):
            self._depth = max(0, self._depth - 1)
            self.tags.append(f"{'  ' * self._depth}</{tag}>")

    left_parser = TagExtractor()
    right_parser = TagExtractor()
    try:
        left_parser.feed(left)
    except Exception:
        pass
    try:
        right_parser.feed(right)
    except Exception:
        pass

    left_lines = left_parser.tags
    right_lines = right_parser.tags

    diff = list(difflib.unified_diff(
        left_lines, right_lines,
        fromfile="left (DOM)", tofile="right (DOM)",
        lineterm="",
    ))
    return "\n".join(diff)


def _response_timing_diff(left_flow_id: str, right_flow_id: str) -> dict:
    """Compare response timing characteristics between two flows."""
    left_flow = state.get_flow(left_flow_id)
    right_flow = state.get_flow(right_flow_id)

    if not left_flow or not right_flow:
        return {"error": "One or both flows not found"}

    left_resp = left_flow.response
    right_resp = right_flow.response

    if not left_resp or not right_resp:
        return {"error": "One or both flows have no response"}

    left_dur = getattr(left_resp, "duration", 0) or 0
    right_dur = getattr(right_resp, "duration", 0) or 0
    left_size = len(left_resp.body) if left_resp.body else 0
    right_size = len(right_resp.body) if right_resp.body else 0

    diff_ms = abs(left_dur - right_dur)
    diff_size = abs(left_size - right_size)

    # Timing anomaly detection (>2x difference)
    timing_anomaly = False
    if left_dur > 0 and right_dur > 0:
        ratio = max(left_dur, right_dur) / min(left_dur, right_dur)
        timing_anomaly = ratio > 2.0
    else:
        ratio = 0.0

    return {
        "left": {
            "status": left_resp.status_code if left_resp else 0,
            "duration_ms": round(left_dur, 2),
            "size_bytes": left_size,
        },
        "right": {
            "status": right_resp.status_code if right_resp else 0,
            "duration_ms": round(right_dur, 2),
            "size_bytes": right_size,
        },
        "diff_ms": round(diff_ms, 2),
        "diff_size": diff_size,
        "timing_ratio": round(ratio, 2),
        "timing_anomaly": timing_anomaly,
        "note": "Significant timing difference detected — possible blind injection indicator" if timing_anomaly else "",
    }


def compare(req: CompareRequest) -> DiffResult:
    """Diff two items — by flow ID or raw content. Supports line/word/char/json modes."""
    if req.left_flow_id:
        left = _flow_to_text(req.left_flow_id)
    elif req.left_content is not None:
        left = req.left_content
    else:
        left = ""

    if req.right_flow_id:
        right = _flow_to_text(req.right_flow_id)
    elif req.right_content is not None:
        right = req.right_content
    else:
        right = ""

    diff_mode = getattr(req, 'diff_mode', 'line') or 'line'

    if diff_mode == "word":
        diff_text = _word_diff(left, right)
        changes = diff_text.count("[-") + diff_text.count("[+")
    elif diff_mode == "char":
        diff_text = _char_diff(left, right)
        changes = diff_text.count("[-") + diff_text.count("[+")
    elif diff_mode == "json":
        diff_text = _json_diff(left, right)
        changes = sum(1 for line in diff_text.splitlines() if line.startswith("+") or line.startswith("-"))
    elif diff_mode == "html":
        diff_text = _html_structural_diff(left, right)
        changes = sum(1 for line in diff_text.splitlines() if line.startswith("+") or line.startswith("-"))
    else:
        # Default line-level diff
        left_lines = left.splitlines(keepends=True)
        right_lines = right.splitlines(keepends=True)

        diff = list(difflib.unified_diff(
            left_lines, right_lines,
            fromfile="left", tofile="right",
            lineterm="",
        ))
        diff_text = "\n".join(diff)
        changes = sum(1 for line in diff if line.startswith("+") or line.startswith("-"))

    left_lines_count = len(left.splitlines())
    right_lines_count = len(right.splitlines())

    return DiffResult(
        diff=diff_text,
        left_lines=left_lines_count,
        right_lines=right_lines_count,
        changes=changes,
    )
