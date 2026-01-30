"""Tests for the CSRF token pre-check logic.

These tests cover the fix for the aiohttp header serialization error:
    TypeError: Cannot serialize non-str key None

Root cause
----------
alexapy's ``get_customer_history_records`` refreshes the CSRF token when it is
``None`` **or** older than 24 hours.  When the refresh fails (the Amazon page
does not return a ``<meta name="csrf-token">`` tag), ``get_csrf_token()``
returns ``None`` and alexapy assigns that ``None`` as the
``anti-csrftoken-a2z`` HTTP header *value*.  aiohttp's Cython HTTP header
writer (``_http_writer.pyx``) then raises::

    TypeError: Cannot serialize non-str key None

(The error text is misleading — it fires for non-str *values* too.)

The integration guards against this by calling ``ensure_csrf_valid()`` before
every alexapy API call that needs a CSRF token.  ``ensure_csrf_valid`` checks
both the *presence* and the *age* of the token, matching the same thresholds
that alexapy uses internally.
"""

import importlib
import sys
import time
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Bootstrap: import helpers.py directly, avoiding the full package __init__.py
# which pulls in homeassistant and other heavy deps not available in CI.
#
# IMPORTANT: all stubs are temporary – we snapshot sys.modules before adding
# them and restore the original state afterwards so that later test files
# (test_diagnostics, test_sensor, test_switch …) can still import the *real*
# modules when running in an environment where they are installed.
# ---------------------------------------------------------------------------

_ALL_STUBS = [
    "homeassistant",
    "homeassistant.const",
    "homeassistant.core",
    "homeassistant.exceptions",
    "homeassistant.helpers",
    "homeassistant.helpers.entity",
    "homeassistant.helpers.instance_id",
    "dictor",
    "custom_components",
    "custom_components.alexa_media",
    "custom_components.alexa_media.const",
    "custom_components.alexa_media.helpers",
]

# 1. Snapshot current sys.modules for every key we might touch.
_saved: dict[str, ModuleType | None] = {k: sys.modules.get(k) for k in _ALL_STUBS}

# 2. Add lightweight stubs (only where the real module isn't already loaded).
for _mod_name in (
    "homeassistant",
    "homeassistant.const",
    "homeassistant.core",
    "homeassistant.exceptions",
    "homeassistant.helpers",
    "homeassistant.helpers.entity",
    "homeassistant.helpers.instance_id",
):
    if _mod_name not in sys.modules:
        stub = ModuleType(_mod_name)
        stub.CONF_EMAIL = "email"
        stub.CONF_URL = "url"
        stub.HomeAssistant = type("HomeAssistant", (), {})
        stub.ConditionErrorMessage = type(
            "ConditionErrorMessage", (Exception,), {"message": ""}
        )
        stub.Entity = type("Entity", (), {})
        stub.async_get = AsyncMock()
        stub.async_get_instance_id = AsyncMock()
        sys.modules[_mod_name] = stub

if "dictor" not in sys.modules:
    dictor_stub = ModuleType("dictor")
    dictor_stub.dictor = lambda *a, **kw: None
    sys.modules["dictor"] = dictor_stub

for _ns in ("custom_components", "custom_components.alexa_media"):
    if _ns not in sys.modules:
        ns_mod = ModuleType(_ns)
        ns_mod.__path__ = []  # mark as package
        sys.modules[_ns] = ns_mod

if "custom_components.alexa_media.const" not in sys.modules:
    const_stub = ModuleType("custom_components.alexa_media.const")
    const_stub.DATA_ALEXAMEDIA = "alexa_media"
    const_stub.EXCEPTION_TEMPLATE = (
        "An exception of type {} occurred. Arguments:\n{}"
    )
    sys.modules["custom_components.alexa_media.const"] = const_stub

# 3. Import the actual helpers module.
spec = importlib.util.spec_from_file_location(
    "custom_components.alexa_media.helpers",
    "custom_components/alexa_media/helpers.py",
)
helpers_mod = importlib.util.module_from_spec(spec)
sys.modules["custom_components.alexa_media.helpers"] = helpers_mod
spec.loader.exec_module(helpers_mod)

# Grab the symbols we need before restoring sys.modules.
CSRF_MAX_AGE = helpers_mod.CSRF_MAX_AGE
_csrf_needs_refresh = helpers_mod._csrf_needs_refresh
ensure_csrf_valid = helpers_mod.ensure_csrf_valid

# 4. Restore sys.modules to its pre-bootstrap state so other test files
#    that rely on the *real* packages are not affected.
for _key in _ALL_STUBS:
    if _saved[_key] is None:
        sys.modules.pop(_key, None)
    else:
        sys.modules[_key] = _saved[_key]

# ---------------------------------------------------------------------------
# Stub helpers
# ---------------------------------------------------------------------------

_TEST_TOKEN = "test-csrf-value"  # nosec B105


def _make_login_obj(
    csrf_token=None,
    csrf_token_created_at=None,
    csrf_after_refresh=None,
    created_at_after_refresh=None,
):
    """Return a lightweight mock that behaves like AlexaLogin.

    Args:
        csrf_token: initial value of csrf_token.
        csrf_token_created_at: initial creation timestamp (epoch seconds).
        csrf_after_refresh: value csrf_token should have **after**
            get_csrf_token() is awaited.  If an Exception, it will be raised.
        created_at_after_refresh: value of csrf_token_created_at after refresh.
    """
    login = MagicMock()
    login.csrf_token = csrf_token
    login.csrf_token_created_at = csrf_token_created_at
    login.email = "test@example.com"

    async def _refresh():
        if isinstance(csrf_after_refresh, BaseException):
            raise csrf_after_refresh
        if isinstance(csrf_after_refresh, type) and issubclass(
            csrf_after_refresh, BaseException
        ):
            raise csrf_after_refresh()
        login.csrf_token = csrf_after_refresh
        login.csrf_token_created_at = created_at_after_refresh

    login.get_csrf_token = AsyncMock(side_effect=_refresh)
    return login


# ===================================================================
# Unit tests for _csrf_needs_refresh
# ===================================================================


class TestCsrfNeedsRefresh:
    """Direct tests for the _csrf_needs_refresh predicate."""

    def test_token_none(self):
        login = _make_login_obj(csrf_token=None)
        assert _csrf_needs_refresh(login) is True

    def test_token_present_created_at_none(self):
        login = _make_login_obj(csrf_token=_TEST_TOKEN, csrf_token_created_at=None)
        assert _csrf_needs_refresh(login) is True

    def test_token_fresh(self):
        login = _make_login_obj(
            csrf_token=_TEST_TOKEN, csrf_token_created_at=int(time.time())
        )
        assert _csrf_needs_refresh(login) is False

    def test_token_expired(self):
        login = _make_login_obj(
            csrf_token=_TEST_TOKEN,
            csrf_token_created_at=int(time.time()) - CSRF_MAX_AGE - 1,
        )
        assert _csrf_needs_refresh(login) is True

    def test_token_just_within_limit(self):
        login = _make_login_obj(
            csrf_token=_TEST_TOKEN,
            csrf_token_created_at=int(time.time()) - CSRF_MAX_AGE + 60,
        )
        assert _csrf_needs_refresh(login) is False

    def test_missing_created_at_attribute(self):
        """If AlexaLogin lacks csrf_token_created_at entirely, treat as stale."""
        login = MagicMock(spec=[])
        login.csrf_token = _TEST_TOKEN
        # no csrf_token_created_at attribute at all
        assert _csrf_needs_refresh(login) is True


# ===================================================================
# Unit tests for ensure_csrf_valid
# ===================================================================


class TestEnsureCsrfValid:
    """Test the ensure_csrf_valid async helper."""

    @pytest.mark.asyncio
    async def test_fresh_token_no_refresh(self):
        """A fresh token needs no refresh."""
        now = int(time.time())
        login = _make_login_obj(csrf_token=_TEST_TOKEN, csrf_token_created_at=now)
        result = await ensure_csrf_valid(login, "test")
        assert result is True
        login.get_csrf_token.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_none_token_refresh_succeeds(self):
        """None token, refresh succeeds -> True."""
        now = int(time.time())
        login = _make_login_obj(
            csrf_token=None,
            csrf_after_refresh=_TEST_TOKEN,
            created_at_after_refresh=now,
        )
        result = await ensure_csrf_valid(login, "test")
        assert result is True
        login.get_csrf_token.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_none_token_refresh_fails(self):
        """None token, refresh returns None -> False."""
        login = _make_login_obj(
            csrf_token=None,
            csrf_after_refresh=None,
            created_at_after_refresh=None,
        )
        result = await ensure_csrf_valid(login, "test")
        assert result is False
        login.get_csrf_token.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_none_token_refresh_raises(self):
        """None token, refresh raises -> False."""
        login = _make_login_obj(
            csrf_token=None,
            csrf_after_refresh=RuntimeError("network error"),
        )
        result = await ensure_csrf_valid(login, "test")
        assert result is False
        login.get_csrf_token.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_expired_token_refresh_succeeds(self):
        """Expired token (>24 h), refresh succeeds -> True."""
        now = int(time.time())
        login = _make_login_obj(
            csrf_token="old-token",
            csrf_token_created_at=now - CSRF_MAX_AGE - 1,
            csrf_after_refresh="new-token",
            created_at_after_refresh=now,
        )
        result = await ensure_csrf_valid(login, "test")
        assert result is True
        login.get_csrf_token.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_expired_token_refresh_fails(self):
        """Expired token (>24 h), refresh returns None -> False.

        This is the exact scenario that caused the original TypeError:
        alexapy would try to refresh internally, get None, and assign
        it as the header value.
        """
        now = int(time.time())
        login = _make_login_obj(
            csrf_token="old-token",
            csrf_token_created_at=now - CSRF_MAX_AGE - 1,
            csrf_after_refresh=None,
            created_at_after_refresh=None,
        )
        result = await ensure_csrf_valid(login, "test")
        assert result is False
        login.get_csrf_token.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_expired_token_refresh_raises(self):
        """Expired token, refresh raises -> False."""
        now = int(time.time())
        login = _make_login_obj(
            csrf_token="old-token",
            csrf_token_created_at=now - CSRF_MAX_AGE - 1,
            csrf_after_refresh=RuntimeError("fail"),
        )
        result = await ensure_csrf_valid(login, "test")
        assert result is False
        login.get_csrf_token.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_expired_token_refresh_succeeds_but_no_created_at(self):
        """Refresh sets token but not created_at -> still invalid."""
        now = int(time.time())
        login = _make_login_obj(
            csrf_token="old-token",
            csrf_token_created_at=now - CSRF_MAX_AGE - 1,
            csrf_after_refresh="new-token",
            created_at_after_refresh=None,  # created_at not updated
        )
        result = await ensure_csrf_valid(login, "test")
        assert result is False
        login.get_csrf_token.assert_awaited_once()
