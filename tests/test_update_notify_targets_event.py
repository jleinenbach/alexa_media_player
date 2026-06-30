"""Regression tests for last_called event scheduling vs. its caller path.

Round-6 Codex finding (Klasse: foreign side effect in a multi-caller
maintenance helper): ``_update_notify_targets`` scheduled the
``alexa_media_last_called_event`` bus event as its first statement. That helper
has two callers, the genuine ``last_called_change`` push in ``_handle_event``
*and* ``refresh()`` (including ``skip_api=True`` startup polling). The latter
merely observes the stored ``last_called`` value, so the event fired on
startup/polling with stale commands and automations ran on outdated data.

The fix lifts the scheduling out of the helper back into the genuine push path
in ``_handle_event`` (origin/dev behaviour), so ``_update_notify_targets`` is
pure notify-target maintenance again and the event fires exactly once per real
voice action. The round-3 gain (the event stays decoupled from notify
readiness) is preserved because the call sits outside any notify guard.

These tests pin both directions:

* negative: ``_update_notify_targets`` no longer schedules the event;
* positive: the genuine ``_handle_event`` push path schedules it once, even
  when the notify platform is absent (notify-independence, round-3 intent).

A source-structure anchor additionally guards the call topology, because the
full ``_handle_event``/``refresh`` runtime is HA-coupled (Tier 3, declared
coverage exception). Runtime behaviour stays CI-authoritative.
"""

import ast
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from custom_components.alexa_media.const import DATA_ALEXAMEDIA
from custom_components.alexa_media.media_player import AlexaClient

_MEDIA_PLAYER = (
    Path(__file__).resolve().parent.parent
    / "custom_components"
    / "alexa_media"
    / "media_player.py"
)

_SERIAL = "G000SERIAL0000"


def _make_entity(notify_service):
    """Build a bare AlexaClient with just enough state for the helper path."""
    entity = object.__new__(AlexaClient)
    entity.hass = MagicMock()
    entity.hass.data = {DATA_ALEXAMEDIA: {"notify_service": notify_service}}
    login = MagicMock()
    login.email = "user@example.com"
    entity._login = login
    return entity


def _make_push_entity(notify_service):
    """Build a bare AlexaClient able to traverse the genuine push branch."""
    entity = _make_entity(notify_service)
    entity._device_serial_number = _SERIAL
    entity._app_device_list = []
    entity._last_called = False
    entity._last_called_timestamp = None
    entity._last_called_summary = None
    entity._last_called_response = None
    entity.schedule_update_ha_state = MagicMock()
    entity.async_schedule_update_ha_state = MagicMock()
    return entity


def _genuine_event():
    """A genuine last_called_change push for the entity's own serial."""
    return {
        "last_called_change": {
            "serialNumber": _SERIAL,
            "timestamp": "ts-1",
            "summary": "good morning",
            "response": "ok",
        }
    }


# --- Negative direction: the helper must no longer schedule the event ---


@pytest.mark.asyncio
async def test_update_notify_targets_does_not_schedule_event_when_notify_absent():
    """notify_service is None: the helper must NOT schedule the bus event.

    This is the round-6 fix: previously the event fired here on every call,
    including refresh()/startup. The helper is pure notify maintenance now.
    """
    entity = _make_entity(notify_service=None)

    with patch(
        "custom_components.alexa_media.media_player.async_call_later"
    ) as mock_call_later:
        await entity._update_notify_targets()

    mock_call_later.assert_not_called()


@pytest.mark.asyncio
async def test_update_notify_targets_does_not_schedule_event_when_notify_not_ready():
    """notify present but without registered_targets: still no scheduling."""
    not_ready_notify = object()  # truthy, but lacks ``registered_targets``
    entity = _make_entity(notify_service=not_ready_notify)

    with patch(
        "custom_components.alexa_media.media_player.async_call_later"
    ) as mock_call_later:
        await entity._update_notify_targets()

    mock_call_later.assert_not_called()


# --- Positive direction: the genuine push path schedules it, notify-independent ---


@pytest.mark.asyncio
async def test_handle_event_schedules_event_on_genuine_last_called_change():
    """A genuine push schedules the event once, even with notify absent.

    Pins both the round-6 placement (the event comes from the push path) and
    the round-3 intent (it stays decoupled from notify readiness: the notify
    platform is None here, yet the event is still scheduled).
    """
    entity = _make_push_entity(notify_service=None)

    with (
        patch(
            "custom_components.alexa_media.media_player.async_call_later"
        ) as mock_call_later,
        patch(
            "custom_components.alexa_media.media_player.is_http2_enabled",
            return_value=True,
        ),
    ):
        await entity._handle_event(_genuine_event())

    mock_call_later.assert_called_once()


@pytest.mark.asyncio
async def test_handle_event_does_not_schedule_on_non_matching_serial():
    """A last_called_change for a different device must not schedule the event."""
    entity = _make_push_entity(notify_service=None)
    foreign = {
        "last_called_change": {
            "serialNumber": "OTHER_SERIAL",
            "timestamp": "ts-9",
            "summary": "",
            "response": "",
        }
    }

    with (
        patch(
            "custom_components.alexa_media.media_player.async_call_later"
        ) as mock_call_later,
        patch(
            "custom_components.alexa_media.media_player.is_http2_enabled",
            return_value=True,
        ),
    ):
        await entity._handle_event(foreign)

    mock_call_later.assert_not_called()


def test_schedule_last_called_event_is_notify_independent():
    """The scheduler itself defers a bus event regardless of notify state."""
    entity = object.__new__(AlexaClient)
    entity.hass = MagicMock()
    entity._device_serial_number = _SERIAL
    entity._device_name = "Kitchen"
    entity._last_called_timestamp = "ts-1"
    entity._last_called_summary = "s"
    entity._last_called_response = "r"

    with patch(
        "custom_components.alexa_media.media_player.async_call_later"
    ) as mock_call_later:
        entity._schedule_last_called_event()

    mock_call_later.assert_called_once()


# --- Structural anchor: the call topology (Tier 3, HA-coupled runtime) ---


def _function_def(name: str) -> ast.AST:
    """Return the (possibly async) function definition ``name`` from media_player."""
    tree = ast.parse(_MEDIA_PLAYER.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ):
            return node
    raise AssertionError(f"function {name!r} not found in media_player.py")


def _schedules_event(node: ast.AST) -> bool:
    """True if any subtree calls ``self._schedule_last_called_event(...)``."""
    return any(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "_schedule_last_called_event"
        for n in ast.walk(node)
    )


def test_event_scheduled_from_handle_event_not_from_notify_helper():
    """The scheduling call must live in the push path, not the notify helper."""
    assert _schedules_event(
        _function_def("_handle_event")
    ), "_schedule_last_called_event must be called from _handle_event (push path)"
    assert not _schedules_event(
        _function_def("_update_notify_targets")
    ), "_update_notify_targets must not schedule the event (round-6 regression)"
