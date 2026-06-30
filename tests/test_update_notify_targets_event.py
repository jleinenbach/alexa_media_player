"""Regression tests for last_called event scheduling vs. notify readiness.

Round-3 Codex finding (Klasse A / SRP coupling): ``_update_notify_targets`` used
to schedule the ``alexa_media_last_called_event`` bus event only at the very end
of the method, behind the early ``return`` guards that protect the notify-target
refresh. When a last_called update arrived before the notify platform was ready
(startup / not-ready window), the method returned early and the bus event was
never scheduled, so automations missed the update.

The fix extracts the scheduling into ``_schedule_last_called_event`` and calls it
as the first statement, before the notify-readiness guards. These tests pin that
the event is scheduled independently of notify readiness.
"""

from unittest.mock import MagicMock, patch

import pytest

from custom_components.alexa_media.const import DATA_ALEXAMEDIA
from custom_components.alexa_media.media_player import AlexaClient


def _make_entity(notify_service):
    """Build a bare AlexaClient with just enough state for the guard path."""
    entity = object.__new__(AlexaClient)
    entity.hass = MagicMock()
    entity.hass.data = {DATA_ALEXAMEDIA: {"notify_service": notify_service}}
    login = MagicMock()
    login.email = "user@example.com"
    entity._login = login
    return entity


@pytest.mark.asyncio
async def test_event_scheduled_when_notify_service_absent():
    """notify_service is None (startup window): event must still be scheduled."""
    entity = _make_entity(notify_service=None)

    with patch(
        "custom_components.alexa_media.media_player.async_call_later"
    ) as mock_call_later:
        await entity._update_notify_targets()

    # The bus event is scheduled despite the notify platform not being available.
    mock_call_later.assert_called_once()


@pytest.mark.asyncio
async def test_event_scheduled_when_notify_not_ready():
    """notify present but without registered_targets: event must still schedule."""
    not_ready_notify = object()  # truthy, but lacks ``registered_targets``
    entity = _make_entity(notify_service=not_ready_notify)

    with patch(
        "custom_components.alexa_media.media_player.async_call_later"
    ) as mock_call_later:
        await entity._update_notify_targets()

    mock_call_later.assert_called_once()
