"""Structural regression guard for the network-discovery success branch.

During an upstream sync the ``if not api_devices: warning / else`` guard was
introduced, but the dependent processing block (``parse_alexa_entities`` plus
``devices.update`` plus the entity-monitoring setup) stayed on the outer ``if``
indentation, so it ran even on the failure path and overwrote the stored
device snapshot with empty lists. The fix indents that block into the ``else``
(success) branch.

These are source-structure assertions on purpose: the surrounding
``setup_alexa`` coroutine is only reachable through a full Home Assistant
config-entry harness, which is out of scope here (declared coverage exception,
Tier 3). The runtime behaviour stays CI-authoritative. The companion module
``test_parse_alexa_entities_empty`` pins the destructive premise that makes the
placement matter.
"""

import ast
from pathlib import Path

_INIT = (
    Path(__file__).resolve().parent.parent
    / "custom_components"
    / "alexa_media"
    / "__init__.py"
)


def _find_no_api_devices_guard() -> ast.If:
    """Return the ``if not api_devices:`` node from ``__init__.py``."""
    tree = ast.parse(_INIT.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.UnaryOp)
            and isinstance(node.test.op, ast.Not)
            and isinstance(node.test.operand, ast.Name)
            and node.test.operand.id == "api_devices"
        ):
            return node
    raise AssertionError("`if not api_devices:` guard not found in __init__.py")


def _calls_named(nodes: list[ast.stmt], func_name: str) -> bool:
    """True if any subtree of ``nodes`` calls ``func_name`` by bare name."""
    module = ast.Module(body=nodes, type_ignores=[])
    return any(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == func_name
        for n in ast.walk(module)
    )


def _has_devices_update(nodes: list[ast.stmt]) -> bool:
    """True if any subtree of ``nodes`` performs a ``...["devices"].update(...)``."""
    module = ast.Module(body=nodes, type_ignores=[])
    for n in ast.walk(module):
        if (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "update"
            and isinstance(n.func.value, ast.Subscript)
        ):
            key = n.func.value.slice
            if isinstance(key, ast.Constant) and key.value == "devices":
                return True
    return False


class TestNetworkDiscoveryGuard:
    """The discovery processing block must live in the success branch only."""

    def test_parse_alexa_entities_is_in_else_branch(self):
        """``parse_alexa_entities`` must run only when discovery succeeded."""
        guard = _find_no_api_devices_guard()

        assert _calls_named(
            guard.orelse, "parse_alexa_entities"
        ), "parse_alexa_entities must be inside the else (success) branch"
        assert not _calls_named(
            guard.body, "parse_alexa_entities"
        ), "parse_alexa_entities must not run on the empty-response path"

    def test_devices_update_is_in_else_branch(self):
        """The destructive ``devices.update`` must be gated on success."""
        guard = _find_no_api_devices_guard()

        assert _has_devices_update(
            guard.orelse
        ), "devices.update must be inside the else (success) branch"
        assert not _has_devices_update(
            guard.body
        ), "devices.update must not overwrite the snapshot on the failure path"
