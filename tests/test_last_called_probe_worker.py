"""Regression anchor for the last_called probe worker's single-consume-point.

Codex round 2, finding 1: the worker cleared ``last_called_probe_event`` again
after processing a queue item. A push that arrived mid-processing had already
re-set the event; the post-processing ``clear()`` then erased that wake-up, so
rapid consecutive voice commands could leave the newly queued activity idle
(lost wakeup).

The fix establishes a single-consume-point: the event is consumed (``clear()``)
exactly once, at the top of the worker loop right after ``wait()``. Every other
post-processing/preempt ``clear()`` is removed.

The worker is a deeply nested closure inside ``async_setup_entry`` and cannot be
invoked in isolation, so this is a structural regression anchor (same approach as
``test_setup_order.py``): it parses the worker source via AST and pins the
invariant, guarding against re-introduction of the lost-wakeup ``clear()`` calls.
"""

import ast
import pathlib

_SRC = pathlib.Path(__file__).resolve().parent.parent / (
    "custom_components/alexa_media/__init__.py"
)
_EVENT_CLEAR = 'last_called_probe_event"].clear()'
_EVENT_WAIT = 'last_called_probe_event"].wait()'


def _worker_source():
    """Return the source text of the _last_called_probe_worker closure."""
    source = _SRC.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef))
            and node.name == "_last_called_probe_worker"
        ):
            segment = ast.get_source_segment(source, node)
            assert segment is not None
            return segment
    raise AssertionError("_last_called_probe_worker not found")


class TestSingleConsumePoint:
    """The probe event must be consumed at exactly one point in the worker."""

    def test_event_cleared_exactly_once(self):
        """Only the top-of-loop consume may clear the event (no post-clear)."""
        worker = _worker_source()
        clears = worker.count(_EVENT_CLEAR)
        assert clears == 1, (
            f"expected exactly one last_called_probe_event clear() "
            f"(single-consume-point), found {clears}; a post-processing "
            f"clear() re-introduces the lost-wakeup bug"
        )

    def test_clear_is_colocated_with_top_of_loop_wait(self):
        """The single clear() must directly follow the loop's wait() consume."""
        worker = _worker_source()
        lines = worker.splitlines()
        clear_lines = [i for i, ln in enumerate(lines) if _EVENT_CLEAR in ln]
        wait_lines = [i for i, ln in enumerate(lines) if _EVENT_WAIT in ln]

        assert len(clear_lines) == 1
        assert wait_lines, "expected a top-of-loop wait() on the probe event"
        clear_idx = clear_lines[0]
        # The consume clear() sits immediately after a wait() on the same event.
        assert any(0 < clear_idx - w <= 1 for w in wait_lines), (
            "the single clear() must be co-located with the top-of-loop wait() "
            "(consume-on-wake), not in a post-processing branch"
        )
