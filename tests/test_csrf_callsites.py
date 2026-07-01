"""Regression tests for the fork's CSRF guard at an API call site.

The fork guards every alexapy call that needs a CSRF token with
``ensure_csrf_valid`` (PR #22): when the token cannot be made valid, the call
site must short-circuit and never reach the alexapy API (otherwise aiohttp's
header writer crashes on a ``None`` token value). ``ensure_csrf_valid`` itself
is unit-tested in ``test_csrf_precheck.py``; this module locks in the
*integration*: the ``get_history_records`` service skips
``AlexaAPI.get_customer_history_records`` when the guard fails.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

import custom_components.alexa_media.services as services_mod
from custom_components.alexa_media.services import AlexaMediaServices


def _make_services_with_account():
    """Build an AlexaMediaServices with one account and a mock hass."""
    hass = MagicMock()
    accounts = {"test@example.com": {"login_obj": MagicMock()}}
    hass.data = {services_mod.DATA_ALEXAMEDIA: {"accounts": accounts}}
    return AlexaMediaServices(hass, functions={})


def _make_call():
    """A ServiceCall-like mock targeting a valid alexa_media entity."""
    call = MagicMock()
    call.data = {
        services_mod.ATTR_ENTITY_ID: "media_player.echo",
        services_mod.ATTR_NUM_ENTRIES: 5,
    }
    return call


def _patch_entity_registry(monkeypatch):
    """Make ``er.async_get`` resolve the target entity to this integration."""
    entry = MagicMock()
    entry.platform = services_mod.DOMAIN
    entry.unique_id = "serial-1"
    registry = MagicMock()
    registry.async_get.return_value = entry
    monkeypatch.setattr(services_mod.er, "async_get", lambda hass: registry)


class TestGetHistoryRecordsCsrfGuard:
    """The history service must honour the ensure_csrf_valid early return."""

    @pytest.mark.asyncio
    async def test_invalid_csrf_skips_api_call(self, monkeypatch):
        """Guard returns False -> alexapy API must not be reached."""
        _patch_entity_registry(monkeypatch)
        monkeypatch.setattr(
            services_mod, "ensure_csrf_valid", AsyncMock(return_value=False)
        )
        api_mock = AsyncMock(return_value=[])
        monkeypatch.setattr(
            services_mod.AlexaAPI, "get_customer_history_records", api_mock
        )

        svc = _make_services_with_account()
        await svc.get_history_records(_make_call())

        api_mock.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_valid_csrf_proceeds_to_api_call(self, monkeypatch):
        """Guard returns True -> alexapy API is reached (control path)."""
        _patch_entity_registry(monkeypatch)
        monkeypatch.setattr(
            services_mod, "ensure_csrf_valid", AsyncMock(return_value=True)
        )
        api_mock = AsyncMock(return_value=[])
        monkeypatch.setattr(
            services_mod.AlexaAPI, "get_customer_history_records", api_mock
        )

        svc = _make_services_with_account()
        await svc.get_history_records(_make_call())

        api_mock.assert_awaited_once()
