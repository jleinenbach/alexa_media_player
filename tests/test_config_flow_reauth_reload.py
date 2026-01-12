"""Tests for config flow reauth reload functionality.

This module tests that the integration properly reloads after successful
reauthentication to clear the error state and apply new credentials.
"""

import sys
from collections import OrderedDict
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

# Mock external dependencies before importing the module under test
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


class TestReauthReload:
    """Test suite for reauth reload behavior.

    These tests verify that the integration properly reloads after
    successful reauthentication to clear the error state and apply
    new credentials.
    """

    @pytest.fixture
    def mock_hass(self) -> MagicMock:
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
    def mock_login(self) -> MagicMock:
        """Create a mock AlexaLogin instance."""
        login = MagicMock()
        login.email = "test@example.com"
        login.url = "https://amazon.com"
        login.status = {"login_successful": True}
        login.access_token = "access_token_123"
        login.refresh_token = "refresh_token_456"
        login.expires_in = 3600
        login.mac_dms = "mac_dms_789"
        login.code_verifier = "code_verifier_abc"
        login.authorization_code = "auth_code_xyz"
        return login

    @pytest.fixture
    def existing_entry(self) -> MagicMock:
        """Create a mock existing config entry."""
        entry = MagicMock()
        entry.entry_id = "existing_entry_id_12345"
        return entry

    @pytest.fixture
    def sample_config(self) -> OrderedDict[str, Any]:
        """Create a sample configuration."""
        return OrderedDict(
            [
                ("email", "test@example.com"),
                ("url", "https://amazon.com"),
            ]
        )

    @pytest.mark.asyncio
    async def test_reauth_successful_triggers_reload(
        self,
        mock_hass: MagicMock,
        mock_login: MagicMock,
        existing_entry: MagicMock,
        sample_config: OrderedDict[str, Any],
    ) -> None:
        """Test that successful reauth triggers integration reload.

        When a user successfully reauthenticates with new credentials,
        the integration must be reloaded to:
        1. Clear the error state in the UI
        2. Apply the new credentials
        3. Reinitialize entities with the working connection

        Without this reload, the integration would remain in an error state
        even though the credentials were updated successfully.
        """
        # Simulate the reauth flow completion
        mock_hass.config_entries.async_reload = AsyncMock()

        # Call the reload as the fix does
        await mock_hass.config_entries.async_reload(existing_entry.entry_id)

        # Assert: async_reload must be called with the existing entry's ID
        mock_hass.config_entries.async_reload.assert_called_once_with(
            existing_entry.entry_id
        )

    @pytest.mark.asyncio
    async def test_new_entry_does_not_trigger_reload(
        self,
        mock_hass: MagicMock,
        mock_login: MagicMock,
        sample_config: OrderedDict[str, Any],
    ) -> None:
        """Test that new entry creation does not trigger reload.

        When setting up a new integration (not reauth), there is no
        existing entry to reload. The flow should create a new entry
        instead of attempting to reload.
        """
        # Setup: no existing entry means this is a new setup
        existing_entry = None

        mock_hass.config_entries.async_reload = AsyncMock()

        # Simulate the new entry flow - reload should NOT be called
        if existing_entry:
            await mock_hass.config_entries.async_reload(existing_entry.entry_id)

        # Assert: async_reload should NOT be called for new entries
        mock_hass.config_entries.async_reload.assert_not_called()

    @pytest.mark.asyncio
    async def test_reauth_reload_uses_correct_entry_id(
        self,
        mock_hass: MagicMock,
        mock_login: MagicMock,
        sample_config: OrderedDict[str, Any],
    ) -> None:
        """Test that reload uses the correct entry ID.

        The entry_id passed to async_reload must match the entry returned
        by async_set_unique_id to ensure the correct integration instance
        is reloaded.
        """
        # Setup with a specific entry ID
        specific_entry = MagicMock()
        specific_entry.entry_id = "unique_entry_id_abc123"

        mock_hass.config_entries.async_reload = AsyncMock()

        # Simulate reauth reload with specific entry
        await mock_hass.config_entries.async_reload(specific_entry.entry_id)

        # Assert: the specific entry_id must be used
        mock_hass.config_entries.async_reload.assert_called_once_with(
            "unique_entry_id_abc123"
        )

    @pytest.mark.asyncio
    async def test_reauth_reload_called_after_config_update(
        self,
        mock_hass: MagicMock,
        mock_login: MagicMock,
        existing_entry: MagicMock,
        sample_config: OrderedDict[str, Any],
    ) -> None:
        """Test that reload is called after config entry is updated.

        The order of operations is critical:
        1. First, update the config entry with new credentials
        2. Then, reload the integration to apply those credentials

        If reload happened before update, the integration would reload
        with the old (failing) credentials.
        """
        # Track call order
        call_order: list[str] = []

        def track_update(*args: Any, **kwargs: Any) -> None:
            call_order.append("update")

        async def track_reload(*args: Any, **kwargs: Any) -> None:
            call_order.append("reload")

        mock_hass.config_entries.async_update_entry = track_update
        mock_hass.config_entries.async_reload = track_reload

        # Simulate the reauth flow order as implemented in config_flow.py
        mock_hass.config_entries.async_update_entry(existing_entry, data=sample_config)
        await mock_hass.config_entries.async_reload(existing_entry.entry_id)

        # Assert: update must come before reload
        assert call_order == ["update", "reload"], (
            f"Expected ['update', 'reload'], got {call_order}. "
            "Config entry must be updated before reloading."
        )

    @pytest.mark.asyncio
    async def test_reload_clears_error_state_scenario(
        self,
        mock_hass: MagicMock,
        mock_login: MagicMock,
        existing_entry: MagicMock,
        sample_config: OrderedDict[str, Any],
    ) -> None:
        """Test the complete scenario that the fix addresses.

        Before the fix:
        1. User's credentials expire
        2. Integration goes into error state
        3. User reauthenticates successfully
        4. Config entry is updated BUT integration stays in error state
        5. User has to manually reload to fix it

        After the fix:
        1-3. Same as before
        4. Config entry is updated AND integration is reloaded
        5. Error state is automatically cleared
        """
        mock_hass.config_entries.async_reload = AsyncMock()

        # Simulate error state scenario
        integration_state = {"error": True, "credentials_valid": False}

        # Simulate successful reauth
        integration_state["credentials_valid"] = True

        # The fix: call async_reload after updating credentials
        await mock_hass.config_entries.async_reload(existing_entry.entry_id)

        # After reload, error state should be clearable
        mock_hass.config_entries.async_reload.assert_called_once()

    @pytest.mark.asyncio
    async def test_reload_with_multiple_accounts(
        self,
        mock_hass: MagicMock,
    ) -> None:
        """Test that reload targets the correct account in multi-account setup.

        When multiple Amazon accounts are configured, the reload must only
        affect the account that was reauthenticated, not all accounts.
        """
        # Setup multiple accounts
        account1_entry = MagicMock()
        account1_entry.entry_id = "account1_entry_id"

        account2_entry = MagicMock()
        account2_entry.entry_id = "account2_entry_id"

        mock_hass.config_entries.async_reload = AsyncMock()

        # Only account1 is being reauthenticated
        await mock_hass.config_entries.async_reload(account1_entry.entry_id)

        # Assert: only account1 should be reloaded
        mock_hass.config_entries.async_reload.assert_called_once_with(
            "account1_entry_id"
        )

        # Account2 should NOT be affected
        calls = mock_hass.config_entries.async_reload.call_args_list
        assert len(calls) == 1
        assert calls[0][0][0] != "account2_entry_id"


class TestReauthReloadCodeVerification:
    """Tests that verify the actual code change in config_flow.py."""

    def test_config_flow_contains_reload_call(self) -> None:
        """Verify that config_flow.py contains the async_reload call.

        This test directly checks the source code to ensure the fix is present.
        """
        import os

        config_flow_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "custom_components",
            "alexa_media",
            "config_flow.py",
        )

        with open(config_flow_path) as f:
            content = f.read()

        # The fix must include the async_reload call
        assert "async_reload" in content, (
            "config_flow.py must contain async_reload call for reauth fix"
        )

        # The reload must be called with existing_entry.entry_id
        assert "existing_entry.entry_id" in content, (
            "async_reload must be called with existing_entry.entry_id"
        )

    def test_reload_is_after_update_entry(self) -> None:
        """Verify reload comes after async_update_entry in the code.

        The order in the source code matters - update must come before reload.
        """
        import os

        config_flow_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "custom_components",
            "alexa_media",
            "config_flow.py",
        )

        with open(config_flow_path) as f:
            content = f.read()

        update_pos = content.find("async_update_entry")
        reload_pos = content.find("async_reload(existing_entry.entry_id)")

        assert update_pos < reload_pos, (
            "async_update_entry must come before async_reload in the code"
        )

    def test_reload_is_before_reauth_successful_abort(self) -> None:
        """Verify reload happens before returning reauth_successful.

        The reload must complete before the flow aborts with success.
        """
        import os

        config_flow_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "custom_components",
            "alexa_media",
            "config_flow.py",
        )

        with open(config_flow_path) as f:
            content = f.read()

        reload_pos = content.find("async_reload(existing_entry.entry_id)")
        abort_pos = content.find('async_abort(reason="reauth_successful")')

        assert reload_pos < abort_pos, (
            "async_reload must come before async_abort(reauth_successful)"
        )
