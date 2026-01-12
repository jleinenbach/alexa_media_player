"""Fixtures for alexa_media tests."""

import sys
from collections import OrderedDict
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

# Mock external dependencies
sys.modules["alexapy"] = MagicMock()
sys.modules["aiohttp"] = MagicMock()
sys.modules["aiohttp.web"] = MagicMock()
sys.modules["aiohttp.web_response"] = MagicMock()
sys.modules["aiohttp.web_exceptions"] = MagicMock()
sys.modules["awesomeversion"] = MagicMock()
sys.modules["dictor"] = MagicMock()
sys.modules["httpx"] = MagicMock()
sys.modules["voluptuous"] = MagicMock()
sys.modules["yarl"] = MagicMock()
sys.modules["wrapt"] = MagicMock()

# Mock homeassistant modules
mock_ha = MagicMock()
sys.modules["homeassistant"] = mock_ha
sys.modules["homeassistant.config_entries"] = MagicMock()
sys.modules["homeassistant.components"] = MagicMock()
sys.modules["homeassistant.components.http"] = MagicMock()
sys.modules["homeassistant.components.http.view"] = MagicMock()
sys.modules["homeassistant.components.persistent_notification"] = MagicMock()
sys.modules["homeassistant.const"] = MagicMock()
sys.modules["homeassistant.core"] = MagicMock()
sys.modules["homeassistant.data_entry_flow"] = MagicMock()
sys.modules["homeassistant.exceptions"] = MagicMock()
sys.modules["homeassistant.helpers"] = MagicMock()
sys.modules["homeassistant.helpers.network"] = MagicMock()
sys.modules["homeassistant.util"] = MagicMock()


@pytest.fixture
def mock_hass() -> MagicMock:
    """Create a mock Home Assistant instance."""
    hass = MagicMock()
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock()
    hass.config_entries.async_reload = AsyncMock()
    hass.bus = MagicMock()
    hass.bus.async_fire = MagicMock()
    hass.data = {"alexa_media": {"accounts": {}, "config_flows": {}}}
    return hass


@pytest.fixture
def mock_login() -> MagicMock:
    """Create a mock AlexaLogin instance."""
    login = MagicMock()
    login.email = "test@example.com"
    login.url = "https://amazon.com"
    login.status = {"login_successful": True}
    login.stats = {"login_timestamp": "2024-01-01T00:00:00"}
    return login


@pytest.fixture
def mock_existing_entry() -> MagicMock:
    """Create a mock config entry for reauth scenarios."""
    entry = MagicMock()
    entry.entry_id = "test_entry_id_12345"
    entry.data = {"email": "test@example.com", "url": "https://amazon.com"}
    return entry


@pytest.fixture
def sample_config() -> OrderedDict[str, Any]:
    """Create a sample configuration."""
    return OrderedDict(
        [
            ("email", "test@example.com"),
            ("password", "test_password"),
            ("url", "https://amazon.com"),
            ("debug", False),
            ("include_devices", ""),
            ("exclude_devices", ""),
            ("scan_interval", 60),
            ("hass_url", "http://homeassistant.local:8123"),
            ("public_url", ""),
            ("queue_delay", 1.5),
            ("extended_entity_discovery", False),
            ("oauth", {}),
            ("uuid", "test-uuid-1234"),
        ]
    )
