"""Structural regression test: history fetch stays under last_called_api_lock.

Codex flagged that the last_called probe worker computed the request window
inside ``async with account_live["last_called_api_lock"]`` but issued the
expensive ``AlexaAPI.get_customer_history_records`` network call *after* the
``async with`` block, so the fetch was not serialized with service/global
refreshes sharing the lock. A push-triggered probe and a service refresh could
then hit the Alexa history endpoint concurrently, defeating the per-account
rate-limit protection and making 429/backoff failures more likely.

The probe call lives in a deeply nested closure inside ``async_setup_entry``
that cannot be invoked in isolation, so this is a Tier-3 structural anchor
(AST), matching the worker anchors used for earlier rounds. It asserts that the
``get_customer_history_records`` call node is lexically enclosed by an
``async with`` on ``last_called_api_lock``. The mutation counter-proof runs the
same assertion against the pre-fix backup source and requires it to fail.
"""

import ast
from pathlib import Path

import pytest

_INIT = (
    Path(__file__).resolve().parents[1]
    / "custom_components"
    / "alexa_media"
    / "__init__.py"
)
_FETCH = "get_customer_history_records"
_LOCK = "last_called_api_lock"


def _fetch_calls_under_lock(source: str):
    """Return (line, enclosed_by_lock) for each get_customer_history_records call."""
    tree = ast.parse(source)
    results = []

    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self._stack = []

        def visit(self, node):
            self._stack.append(node)
            if isinstance(node, ast.Attribute) and node.attr == _FETCH:
                enclosed = False
                for ancestor in self._stack:
                    if isinstance(ancestor, ast.AsyncWith):
                        for item in ancestor.items:
                            segment = ast.get_source_segment(source, item.context_expr)
                            if segment and _LOCK in segment:
                                enclosed = True
                if results is not None:
                    results.append((node.lineno, enclosed))
            self.generic_visit(node)
            self._stack.pop()

    Visitor().visit(tree)
    return results


def test_history_fetch_is_serialized_under_lock():
    """The probe history fetch must be lexically inside the api-lock block."""
    calls = _fetch_calls_under_lock(_INIT.read_text())

    assert calls, f"no {_FETCH} call found in __init__.py"
    unguarded = [line for line, enclosed in calls if not enclosed]
    assert not unguarded, (
        f"{_FETCH} call(s) at line(s) {unguarded} are not enclosed by "
        f"`async with ...{_LOCK}`; the fetch escapes the serializing lock."
    )


def test_anchor_is_sharp_against_pre_fix_backup():
    """Mutation counter-proof: the pre-fix backup must trip the anchor.

    Guards against a tautological anchor: if the backup (fetch outside the lock)
    is available, the same check must report the fetch as unguarded.
    """
    backup = Path("/app/memory/_store/backups/__init__.py.runde4-bak")
    if not backup.exists():
        pytest.skip("pre-fix backup not available in this environment")

    calls = _fetch_calls_under_lock(backup.read_text())
    assert calls, f"no {_FETCH} call found in backup"
    assert any(
        not enclosed for _, enclosed in calls
    ), "expected the pre-fix backup to have the fetch outside the lock"
