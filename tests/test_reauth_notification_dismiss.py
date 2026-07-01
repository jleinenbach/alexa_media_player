"""Regression guards for reauth notification dismissal (Codex round 8, P3).

The reauth persistent-notification id changed format across releases. Version
4.13.6 (commit 3b46271) created it as a separator-less
``f"alexa_media_{slugify(email)}{slugify(url[7:])}"``; the current code uses the
host-based :func:`reauth_notification_id`. A dismiss that only removes the
current id leaves any notification persisted by an older release orphaned.

The fix routes every reauth dismiss through
:func:`dismiss_reauth_notification`, which removes both the current and every
historic id. These guards lock the class in two ways:

1. a behaviour test that the helper dismisses current *and* legacy ids, and
2. a structural class-lock that no dismiss call anywhere in the component
   (except ``helpers.py``, the single legitimate dismiss path) is fed from
   ``reauth_notification_id`` -- whether inline, through a local variable, or
   via an aliased import -- so a future site cannot silently bypass the
   migration helper.

The call sites live inside Home Assistant config-flow/unload harness flows that
are out of scope for a unit test (declared coverage exception, Tier 3); the
structural guard secures their correctness statically instead.
"""

from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock, patch

from homeassistant.util import slugify

from custom_components.alexa_media.helpers import (
    dismiss_reauth_notification,
    legacy_reauth_notification_ids,
    reauth_notification_id,
)

_COMPONENT = (
    Path(__file__).resolve().parent.parent / "custom_components" / "alexa_media"
)
_EMAIL = "user@example.com"
_URL = "https://alexa.amazon.co.uk"
# helpers.py is the one legitimate place allowed to dismiss a reauth id.
_HELPER_FILE = "helpers.py"


def _local_names_for(tree: ast.AST, imported_name: str) -> set[str]:
    """Local names bound to ``imported_name`` via ``from ... import`` (+ aliases)."""
    names = {imported_name}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == imported_name:
                    names.add(alias.asname or alias.name)
    return names


def _is_call_to(node: ast.AST, names: set[str], attr: str) -> bool:
    """True when ``node`` is a call to one of ``names`` (Name) or ``.attr`` (Attribute)."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in names
    if isinstance(func, ast.Attribute):
        return func.attr == attr
    return False


def _reauth_dismiss_bypass_calls(source: str) -> list[ast.Call]:
    """Return dismiss calls whose id derives from reauth_notification_id.

    Catches three bypass shapes so the lock cannot be trivially evaded:
    inline ``async_dismiss(hass, reauth_notification_id(...))``, a local
    variable assigned from ``reauth_notification_id(...)`` that is then
    dismissed, and calls reached through aliased imports of either symbol.
    """
    tree = ast.parse(source)
    dismiss_names = _local_names_for(tree, "async_dismiss")
    reauth_names = _local_names_for(tree, "reauth_notification_id")

    # Local variables assigned from a reauth_notification_id(...) call.
    tainted: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and _is_call_to(
            node.value, reauth_names, "reauth_notification_id"
        ):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    tainted.add(target.id)

    hits: list[ast.Call] = []
    for node in ast.walk(tree):
        if not _is_call_to(node, dismiss_names, "async_dismiss"):
            continue
        for inner in ast.walk(node):
            if _is_call_to(inner, reauth_names, "reauth_notification_id"):
                hits.append(node)
                break
            if isinstance(inner, ast.Name) and inner.id in tainted:
                hits.append(node)
                break
    return hits


def _guarded_sources() -> dict[str, str]:
    """Component sources subject to the class-lock (all *.py except helpers.py)."""
    return {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(_COMPONENT.glob("*.py"))
        if path.name != _HELPER_FILE
    }


class TestDismissReauthNotificationBehaviour:
    """The helper must dismiss the current id and every historic id."""

    def test_dismisses_current_and_legacy_ids(self):
        hass = MagicMock()
        with patch(
            "custom_components.alexa_media.helpers.async_dismiss"
        ) as mock_dismiss:
            dismiss_reauth_notification(hass, _EMAIL, _URL)
        dismissed = {call.args[1] for call in mock_dismiss.call_args_list}
        assert reauth_notification_id(_EMAIL, _URL) in dismissed
        for legacy_id in legacy_reauth_notification_ids(_EMAIL, _URL):
            assert legacy_id in dismissed

    def test_legacy_id_matches_4_13_6_format(self):
        expected = f"alexa_media_{slugify(_EMAIL)}{slugify(_URL[7:])}"
        assert legacy_reauth_notification_ids(_EMAIL, _URL) == [expected]

    def test_current_and_legacy_ids_differ(self):
        current = reauth_notification_id(_EMAIL, _URL)
        assert current not in legacy_reauth_notification_ids(_EMAIL, _URL)


class TestReauthDismissClassLock:
    """No reauth dismiss outside helpers.py may be fed from reauth_notification_id."""

    def test_no_bypass_across_component(self):
        for name, source in _guarded_sources().items():
            assert not _reauth_dismiss_bypass_calls(source), (
                f"{name}: a dismiss fed from reauth_notification_id(...) was "
                "found; route reauth dismissal through "
                "helpers.dismiss_reauth_notification so every historic id is "
                "covered"
            )


class TestClassLockIsSharp:
    """The guard itself must catch the realistic bypass shapes (not just inline)."""

    def test_catches_inline_call(self):
        src = (
            "from homeassistant.components.persistent_notification import async_dismiss\n"
            "from .helpers import reauth_notification_id\n"
            "async_dismiss(hass, reauth_notification_id(email, url))\n"
        )
        assert _reauth_dismiss_bypass_calls(src)

    def test_catches_variable_indirection(self):
        # exactly the pre-round-8 pattern that this fix removed
        src = (
            "from homeassistant.components.persistent_notification import async_dismiss\n"
            "from .helpers import reauth_notification_id\n"
            "nid = reauth_notification_id(email, url)\n"
            "async_dismiss(hass, nid)\n"
        )
        assert _reauth_dismiss_bypass_calls(src)

    def test_catches_aliased_imports(self):
        src = (
            "from homeassistant.components.persistent_notification import "
            "async_dismiss as ad\n"
            "from .helpers import reauth_notification_id as rid\n"
            "ad(hass, rid(email, url))\n"
        )
        assert _reauth_dismiss_bypass_calls(src)

    def test_ignores_unrelated_dismiss(self):
        src = (
            "from homeassistant.components.persistent_notification import async_dismiss\n"
            'async_dismiss(hass, "some_other_notification")\n'
        )
        assert not _reauth_dismiss_bypass_calls(src)
