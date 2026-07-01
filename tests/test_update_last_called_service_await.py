"""Regression tests for update_last_called service completion semantics.

Codex flagged that ``last_call_handler`` scheduled ``_run_update_last_called``
via ``async_create_task`` and returned immediately. Home Assistant treats a
service call as finished once its handler returns, so the service completed
before the ``last_called`` refresh had actually run; a following automation
step could then read the stale state or notify target. The fix collects the
per-account tasks and awaits them (``asyncio.gather(..., return_exceptions=True)``)
before the handler returns, so service completion means the refresh finished.

These tests exercise the public ``last_call_handler`` and assert the observable
completion behaviour, not the internal closure.
"""

import asyncio
from unittest.mock import MagicMock

import pytest

import custom_components.alexa_media.services as services_mod
from custom_components.alexa_media.services import AlexaMediaServices

_KEY = "service_update_last_called_task"


def _make_services(update_fn, emails=("test@example.com",)):
    """AlexaMediaServices whose async_create_task creates real asyncio tasks."""
    hass = MagicMock()
    accounts = {email: {"login_obj": MagicMock()} for email in emails}
    hass.data = {services_mod.DATA_ALEXAMEDIA: {"accounts": accounts}}
    hass.async_create_task = lambda coro, name=None: asyncio.ensure_future(coro)
    svc = AlexaMediaServices(hass, functions={"update_last_called": update_fn})
    return svc, accounts


def _make_call():
    call = MagicMock()
    call.data = {services_mod.ATTR_EMAIL: None}  # all accounts
    return call


class TestUpdateLastCalledServiceAwait:
    """Service completion must imply the last_called refresh has finished."""

    @pytest.mark.asyncio
    async def test_handler_awaits_refresh_completion(self):
        """The handler returns only after the scheduled refresh has completed.

        Under the old fire-and-forget implementation the handler returned while
        the task was still pending, so ``completed`` would be unset at return.
        """
        completed = asyncio.Event()

        async def slow_update(login_obj):
            # Require several event-loop iterations so a fire-and-forget handler
            # would demonstrably return before this finishes.
            for _ in range(5):
                await asyncio.sleep(0)
            completed.set()

        svc, _ = _make_services(slow_update)
        await svc.last_call_handler(_make_call())

        assert completed.is_set(), "handler returned before the refresh completed"

    @pytest.mark.asyncio
    async def test_handler_clears_handle_after_completion(self):
        """A completed refresh leaves no dangling task handle behind."""

        async def quick_update(login_obj):
            return None

        svc, accounts = _make_services(quick_update)
        await svc.last_call_handler(_make_call())

        assert _KEY not in accounts["test@example.com"]

    @pytest.mark.asyncio
    async def test_multiple_accounts_refresh_concurrently(self):
        """Multiple accounts are refreshed concurrently, not serialized.

        Guards the rejected alternative (awaiting each task inside the loop):
        both updates must have started before either is allowed to finish.
        """
        started = {"a@example.com": asyncio.Event(), "b@example.com": asyncio.Event()}
        release = asyncio.Event()
        seen_both_running = asyncio.Event()

        async def update(login_obj):
            # Identify the account by which started-event is still unset.
            for email, event in started.items():
                if not event.is_set():
                    event.set()
                    break
            if all(event.is_set() for event in started.values()):
                seen_both_running.set()
                release.set()
            await release.wait()

        svc, _ = _make_services(update, emails=tuple(started))
        await svc.last_call_handler(_make_call())

        assert seen_both_running.is_set(), "accounts were refreshed serially"

    @pytest.mark.asyncio
    async def test_cancelled_sibling_task_does_not_break_handler(self):
        """A task cancelled by a rapid re-invocation must not fail this call.

        ``return_exceptions=True`` keeps the swallowed CancelledError of a
        superseded task from propagating out of the awaiting handler.
        """
        release = asyncio.Event()

        async def blocking_update(login_obj):
            await release.wait()

        svc, accounts = _make_services(blocking_update)
        account = accounts["test@example.com"]

        # First service call runs concurrently and blocks awaiting its task.
        call1 = asyncio.ensure_future(svc.last_call_handler(_make_call()))
        await asyncio.sleep(0)
        task1 = account[_KEY]
        await asyncio.sleep(0)  # let task1 start and block on release

        # Second service call cancels task1, stores and awaits a replacement.
        call2 = asyncio.ensure_future(svc.last_call_handler(_make_call()))
        await asyncio.sleep(0)
        task2 = account[_KEY]
        assert task1 is not task2

        # call1 awaits gather(task1); task1 was cancelled. With
        # return_exceptions=True this must complete without raising.
        await call1

        # Release task2 so call2 (and the suite) can finish cleanly.
        release.set()
        await call2
