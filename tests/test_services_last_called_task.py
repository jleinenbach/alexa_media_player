"""Regression tests for the last_called service task-handle lifecycle.

Codex flagged that ``_run_update_last_called``'s ``finally`` popped the stored
task handle unconditionally. On a rapid second invocation the first task is
cancelled and a replacement is stored under the same key, but the cancelled
task's ``finally`` then dropped the *live replacement's* handle, so later calls
or unload could no longer cancel/track it. The fix only clears the handle when
it still points at the current task (``asyncio.current_task()``).

These tests exercise the public ``last_call_handler`` and assert the observable
state of ``service_update_last_called_task`` rather than the closure itself.
"""

import asyncio
import contextlib
from unittest.mock import MagicMock

import pytest

import custom_components.alexa_media.services as services_mod
from custom_components.alexa_media.services import AlexaMediaServices

_EMAIL = "test@example.com"
_KEY = "service_update_last_called_task"


def _make_services(update_fn):
    """AlexaMediaServices whose async_create_task creates real asyncio tasks."""
    hass = MagicMock()
    accounts = {_EMAIL: {"login_obj": MagicMock()}}
    hass.data = {services_mod.DATA_ALEXAMEDIA: {"accounts": accounts}}
    hass.async_create_task = lambda coro, name=None: asyncio.ensure_future(coro)
    svc = AlexaMediaServices(hass, functions={"update_last_called": update_fn})
    return svc, accounts[_EMAIL]


def _make_call():
    call = MagicMock()
    call.data = {services_mod.ATTR_EMAIL: None}  # all accounts
    return call


class TestLastCalledTaskHandle:
    """Lifecycle of the per-account update_last_called task handle."""

    @pytest.mark.asyncio
    async def test_single_invocation_clears_own_handle(self):
        """A lone task cleans up its own handle on completion."""

        async def quick_update(login_obj):
            return None

        svc, account = _make_services(quick_update)
        await svc.last_call_handler(_make_call())
        task = account[_KEY]
        await task

        assert _KEY not in account

    @pytest.mark.asyncio
    async def test_rapid_second_invocation_keeps_live_handle(self):
        """The cancelled first task must not drop the replacement's handle.

        This is the regression: under the old unconditional ``pop`` the first
        task's ``finally`` removed the live replacement, leaving no handle.
        """
        release = asyncio.Event()

        async def blocking_update(login_obj):
            await release.wait()

        svc, account = _make_services(blocking_update)

        # First invocation: task1 created, stored, blocks on `release`.
        await svc.last_call_handler(_make_call())
        task1 = account[_KEY]
        await asyncio.sleep(0)  # let task1 start and block

        # Second invocation: cancels task1, stores task2 under the same key.
        await svc.last_call_handler(_make_call())
        task2 = account[_KEY]
        assert task1 is not task2

        # Drive task1 to completion so its finally runs after cancellation.
        with contextlib.suppress(asyncio.CancelledError):
            await task1

        # The live replacement's handle must survive (not popped by task1).
        assert account.get(_KEY) is task2

        # Cleanup: release task2; it owns the handle and pops it.
        release.set()
        await task2
        assert _KEY not in account
