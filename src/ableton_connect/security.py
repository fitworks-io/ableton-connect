"""Fail-closed tool policy and local operator approval."""
from __future__ import annotations

import json
import sys

# Names are deliberately explicit: unknown tools, even get_* tools, need approval.
READ_ONLY_TOOLS = frozenset({
    "get_session_info", "get_track_info", "get_clip_info", "get_device_info",
    "get_device_parameters", "get_browser_tree", "get_browser_items",
})


def confirm_edit(name: str, arguments: dict | None) -> bool:
    if not sys.stdin.isatty():
        return False
    # JSON escapes terminal control characters in untrusted argument values.
    preview = json.dumps({"tool": name, "arguments": arguments}, ensure_ascii=True)
    print("\nAbleton edit requested (save a backup first):\n" + preview, flush=True)
    try:
        return input("Approve this one call? Type APPROVE: ").strip() == "APPROVE"
    except (EOFError, KeyboardInterrupt):
        return False
