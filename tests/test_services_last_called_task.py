"""Regression tests for the last_called service task-handle lifecycle.

Codex flagged that ``_run_update_last_called``'s ``finally`` popped the stored
task handle unconditionally. On a rapid second invocation the first task is
cancelled and a replacement is stored under the same key, but the cancelled
task's ``finally`` then dropped the *live replacement's* handle, so later calls
or unload could no longer cancel/track it. The fix only clears the handle when
it still points at the current task (``asyncio.current_task()``).

These tests exercise the public ``last_call_handler`` and assert the observable
state of ``service_update_last_called_task`` rather than the closure itself.

Note: ``last_call_handler`` now awaits the scheduled refreshes before returning
(HA service-completion contract, see ``test_update_last_called_service_await``),
so the cancel-and-replace invariant is exercised across *concurrent* service
calls rather than a fire-and-forget second call.
"""

import asyncio
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
        """A lone task cleans up its own handle once the handler completes.

        The handler now awaits the refresh, so the task has already finished and
        popped its own handle by the time ``last_call_handler`` returns.
        """

        async def quick_update(login_obj):
            return None

        svc, account = _make_services(quick_update)
        await svc.last_call_handler(_make_call())

        assert _KEY not in account

    @pytest.mark.asyncio
    async def test_rapid_second_invocation_keeps_live_handle(self):
        """The cancelled first task must not drop the replacement's handle.

        This is the regression: under the old unconditional ``pop`` the first
        task's ``finally`` removed the live replacement, leaving no handle.
        Because the handler now awaits its task, the two service calls run
        concurrently: the first blocks awaiting task1 while the second cancels
        task1 and stores task2 under the same key.
        """
        release = asyncio.Event()

        async def blocking_update(login_obj):
            await release.wait()

        svc, account = _make_services(blocking_update)

        # First service call: creates task1, stores it, then blocks awaiting it.
        call1 = asyncio.ensure_future(svc.last_call_handler(_make_call()))
        await asyncio.sleep(0)  # let handler1 create task1 and start awaiting
        task1 = account[_KEY]
        await asyncio.sleep(0)  # let task1 start and block on `release`

        # Second service call: cancels task1, stores task2 under the same key.
        call2 = asyncio.ensure_future(svc.last_call_handler(_make_call()))
        await asyncio.sleep(0)
        task2 = account[_KEY]
        assert task1 is not task2

        # task1 was cancelled by call2; call1's gather(return_exceptions=True)
        # swallows the CancelledError and completes after task1's finally runs.
        await call1

        # The live replacement's handle must survive (not popped by task1).
        assert account.get(_KEY) is task2

        # Cleanup: release task2; it owns the handle and pops it, call2 returns.
        release.set()
        await call2
        assert _KEY not in account
