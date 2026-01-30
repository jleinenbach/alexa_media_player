"""Tests for the CSRF token pre-check logic.

These tests cover the fix for the aiohttp header serialization error:
    TypeError: Cannot serialize non-str key None

The root cause is that alexapy passes login.csrf_token as the
"anti-csrftoken-a2z" HTTP header value.  When csrf_token is None,
aiohttp's Cython HTTP writer rejects the non-string value with the
TypeError above.  The integration now pre-checks the token before
calling AlexaAPI methods that rely on it and either refreshes it or
skips the call entirely.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Minimal stub helpers so we can exercise the CSRF pre-check logic without
# importing homeassistant or the full integration.
# ---------------------------------------------------------------------------


def _make_login_obj(csrf_token=None, csrf_after_refresh=None):
    """Return a lightweight mock that behaves like AlexaLogin.

    Args:
        csrf_token: initial value of csrf_token.
        csrf_after_refresh: value csrf_token should have **after**
            get_csrf_token() is awaited.  If this is an Exception
            *class* or *instance*, get_csrf_token() will raise it.
    """
    login = MagicMock()
    login.csrf_token = csrf_token

    async def _refresh():
        if isinstance(csrf_after_refresh, BaseException):
            raise csrf_after_refresh
        if isinstance(csrf_after_refresh, type) and issubclass(
            csrf_after_refresh, BaseException
        ):
            raise csrf_after_refresh()
        login.csrf_token = csrf_after_refresh

    login.get_csrf_token = AsyncMock(side_effect=_refresh)
    return login


_TEST_TOKEN = "test-csrf-value"  # nosec B105


# ===================================================================
# Tests for update_last_called CSRF pre-check  (__init__.py)
# ===================================================================


class TestUpdateLastCalledCsrfPrecheck:
    """Test the CSRF pre-check in update_last_called."""

    # -- helper that replicates **only** the CSRF pre-check + API-call
    #    portion of update_last_called (lines 826-859 of __init__.py) ---

    @staticmethod
    async def _run_update_last_called(login_obj, email="test@example.com"):
        """Replicate the CSRF pre-check and API call in update_last_called.

        Returns a dict with:
            skipped  - True if the function returned before the API call
            api_called - True if AlexaAPI.get_last_device_serial was invoked
            last_called - the value returned by the (mocked) API, or None
        """
        result = {"skipped": False, "api_called": False, "last_called": None}
        last_called = None  # simulate: no prior value

        # -- Begin code-under-test (mirrors __init__.py:826-859) -------
        if not last_called or not (last_called and last_called.get("summary")):
            # CSRF pre-check
            if login_obj.csrf_token is None:
                try:
                    await login_obj.get_csrf_token()
                except Exception:  # pylint: disable=broad-except
                    result["skipped"] = True
                    return result
                if login_obj.csrf_token is None:
                    result["skipped"] = True
                    return result

            # Simulate the API call (we mock it below)
            try:
                last_called = await login_obj._api_get_last_device_serial()
                result["api_called"] = True
                result["last_called"] = last_called
            except TypeError:
                result["skipped"] = True
                return result
        # -- End code-under-test ----------------------------------------

        return result

    # 1) csrf_token is already valid -> API call proceeds
    @pytest.mark.asyncio
    async def test_csrf_token_valid_calls_api(self):
        """When csrf_token is not None, the API call should proceed."""
        login = _make_login_obj(csrf_token=_TEST_TOKEN)
        login._api_get_last_device_serial = AsyncMock(
            return_value={"serialNumber": "ABC", "timestamp": 123}
        )

        result = await self._run_update_last_called(login)

        assert result["api_called"] is True
        assert result["skipped"] is False
        login.get_csrf_token.assert_not_awaited()

    # 2) csrf_token is None -> refresh succeeds -> API call proceeds
    @pytest.mark.asyncio
    async def test_csrf_none_refresh_succeeds_calls_api(self):
        """When csrf_token is None but refresh succeeds, the API should be called."""
        login = _make_login_obj(csrf_token=None, csrf_after_refresh="refreshed-token")
        login._api_get_last_device_serial = AsyncMock(
            return_value={"serialNumber": "ABC", "timestamp": 123}
        )

        result = await self._run_update_last_called(login)

        assert result["api_called"] is True
        assert result["skipped"] is False
        login.get_csrf_token.assert_awaited_once()

    # 3) csrf_token is None -> refresh raises Exception -> skip
    @pytest.mark.asyncio
    async def test_csrf_none_refresh_raises_skips(self):
        """When csrf_token is None and refresh raises, the call should be skipped."""
        login = _make_login_obj(
            csrf_token=None, csrf_after_refresh=RuntimeError("network error")
        )
        login._api_get_last_device_serial = AsyncMock()

        result = await self._run_update_last_called(login)

        assert result["skipped"] is True
        assert result["api_called"] is False
        login.get_csrf_token.assert_awaited_once()
        login._api_get_last_device_serial.assert_not_awaited()

    # 4) csrf_token is None -> refresh completes but token still None -> skip
    @pytest.mark.asyncio
    async def test_csrf_none_refresh_still_none_skips(self):
        """When refresh completes but token remains None, the call should be skipped."""
        login = _make_login_obj(csrf_token=None, csrf_after_refresh=None)
        login._api_get_last_device_serial = AsyncMock()

        result = await self._run_update_last_called(login)

        assert result["skipped"] is True
        assert result["api_called"] is False
        login.get_csrf_token.assert_awaited_once()
        login._api_get_last_device_serial.assert_not_awaited()

    # 5) csrf_token is valid but API raises TypeError -> handled gracefully
    @pytest.mark.asyncio
    async def test_csrf_valid_api_raises_typeerror(self):
        """When csrf_token is valid but the API raises TypeError, it is caught."""
        login = _make_login_obj(csrf_token=_TEST_TOKEN)
        login._api_get_last_device_serial = AsyncMock(
            side_effect=TypeError("Cannot serialize non-str key None")
        )

        result = await self._run_update_last_called(login)

        assert result["skipped"] is True
        assert result["api_called"] is False

    # 6) last_called already has a summary -> pre-check and API call skipped
    @pytest.mark.asyncio
    async def test_last_called_with_summary_skips_everything(self):
        """When last_called already has a summary, no API call or CSRF check needed."""
        login = _make_login_obj(csrf_token=None)
        login._api_get_last_device_serial = AsyncMock()

        # Directly test the outer condition
        last_called = {"summary": "Turn on the lights", "serialNumber": "ABC"}
        if not last_called or not (last_called and last_called.get("summary")):
            pytest.fail("Should not enter the branch when summary is present")

        # Verify: the condition is False, so no refresh or API call
        login.get_csrf_token.assert_not_awaited()
        login._api_get_last_device_serial.assert_not_awaited()


# ===================================================================
# Tests for _collect_history_for_account CSRF pre-check  (services.py)
# ===================================================================


class TestCollectHistoryCsrfPrecheck:
    """Test the CSRF pre-check in _collect_history_for_account."""

    @staticmethod
    async def _run_collect_history(login_obj):
        """Replicate the CSRF pre-check from _collect_history_for_account.

        Returns a dict with:
            skipped    - True if the function returned before the API call
            api_called - True if get_customer_history_records was invoked
            records    - the data returned by the mock, or None
        """
        result = {"skipped": False, "api_called": False, "records": None}

        # -- Begin code-under-test (mirrors services.py:292-319) -------
        if login_obj.csrf_token is None:
            try:
                await login_obj.get_csrf_token()
            except Exception:  # pylint: disable=broad-except
                result["skipped"] = True
                return result
            if login_obj.csrf_token is None:
                result["skipped"] = True
                return result

        history_data = await login_obj._api_get_customer_history_records()
        result["api_called"] = True
        if not history_data:
            return result

        result["records"] = history_data
        # -- End code-under-test ----------------------------------------

        return result

    # 1) csrf_token valid -> API proceeds
    @pytest.mark.asyncio
    async def test_csrf_token_valid_calls_api(self):
        """When csrf_token is not None, the history API should be called."""
        login = _make_login_obj(csrf_token=_TEST_TOKEN)
        login._api_get_customer_history_records = AsyncMock(
            return_value=[{"description": {"summary": "hello"}}]
        )

        result = await self._run_collect_history(login)

        assert result["api_called"] is True
        assert result["skipped"] is False
        assert result["records"] is not None
        login.get_csrf_token.assert_not_awaited()

    # 2) csrf_token None -> refresh succeeds -> API proceeds
    @pytest.mark.asyncio
    async def test_csrf_none_refresh_succeeds_calls_api(self):
        """When csrf_token is None but refresh works, the API should be called."""
        login = _make_login_obj(csrf_token=None, csrf_after_refresh="refreshed-token")
        login._api_get_customer_history_records = AsyncMock(
            return_value=[{"description": {"summary": "hello"}}]
        )

        result = await self._run_collect_history(login)

        assert result["api_called"] is True
        assert result["skipped"] is False
        login.get_csrf_token.assert_awaited_once()

    # 3) csrf_token None -> refresh raises -> skip
    @pytest.mark.asyncio
    async def test_csrf_none_refresh_raises_skips(self):
        """When refresh raises an exception, the history call should be skipped."""
        login = _make_login_obj(
            csrf_token=None, csrf_after_refresh=RuntimeError("fail")
        )
        login._api_get_customer_history_records = AsyncMock()

        result = await self._run_collect_history(login)

        assert result["skipped"] is True
        assert result["api_called"] is False
        login.get_csrf_token.assert_awaited_once()
        login._api_get_customer_history_records.assert_not_awaited()

    # 4) csrf_token None -> refresh ok but still None -> skip
    @pytest.mark.asyncio
    async def test_csrf_none_refresh_still_none_skips(self):
        """When refresh completes but token remains None, the call should be skipped."""
        login = _make_login_obj(csrf_token=None, csrf_after_refresh=None)
        login._api_get_customer_history_records = AsyncMock()

        result = await self._run_collect_history(login)

        assert result["skipped"] is True
        assert result["api_called"] is False
        login.get_csrf_token.assert_awaited_once()
        login._api_get_customer_history_records.assert_not_awaited()

    # 5) csrf_token valid but API returns empty -> api_called True, records None
    @pytest.mark.asyncio
    async def test_csrf_valid_api_returns_empty(self):
        """When the API returns empty data, api_called is True but records is None."""
        login = _make_login_obj(csrf_token=_TEST_TOKEN)
        login._api_get_customer_history_records = AsyncMock(return_value=[])

        result = await self._run_collect_history(login)

        assert result["api_called"] is True
        assert result["records"] is None
        login.get_csrf_token.assert_not_awaited()

    # 6) csrf_token valid but API returns None -> api_called True, records None
    @pytest.mark.asyncio
    async def test_csrf_valid_api_returns_none(self):
        """When the API returns None, api_called is True but records is None."""
        login = _make_login_obj(csrf_token=_TEST_TOKEN)
        login._api_get_customer_history_records = AsyncMock(return_value=None)

        result = await self._run_collect_history(login)

        assert result["api_called"] is True
        assert result["records"] is None
        login.get_csrf_token.assert_not_awaited()
