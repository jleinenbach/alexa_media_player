# tests/test_cookie_login_no_init_bypass.py
"""Structural regression lock against the cookie-login init bypass (PR #25).

An upstream sync (upstream commit ``cda0e56f``, PR #3445) introduced a
"fast cookie boot" shortcut inside ``async_setup_entry``: on a valid stored
cookie it probed ``https://alexa.amazon.com/api/bootstrap`` directly, then set
``login.status["login_successful"] = True`` and called ``check_domain()`` +
``finalize_login()``, guarding away the real ``await login.login(cookies=...)``
via a ``cookie_login_ok`` flag.

That is the "login marked complete without alexapy initialization" class:
``finalize_login()`` only flips the status flag / saves the cookie, while the
actual token/capability/CSRF initialization lives in ``login.login()`` ->
``test_loggedin()`` (``get_tokens``/``register_capabilities``/
``exchange_token_for_cookies``/``get_csrf``). Skipping it leaves
``AlexaLogin`` partially initialized. ``login.login(cookies=...)`` already
short-circuits via ``test_loggedin`` on valid cookies, so calling it
unconditionally is both correct and cheap; the probe was a redundant
optimization that dropped initialization.

These are source-structure (AST) assertions on purpose: ``async_setup_entry``
is only reachable through a full Home Assistant config-entry harness, which is
out of scope here (declared coverage exception, Tier 3; runtime behaviour stays
CI-authoritative). The guards lock the bypass by its markers (the
``/api/bootstrap`` probe URL, the ``finalize_login``/``check_domain``/
``cookie_login_ok`` markers and the ``login_successful`` assignment) and require
the real ``login.login(cookies=...)`` to run unconditionally, not nested under a
conditional-skip construct (``if``/``while``/``for``/``match``). That covers the
historical upstream variant (``cda0e56f``) and any marker-based reintroduction;
it does not claim to prove the absence of every conceivable control-flow shape
(the outer ``try/except`` wrapping the boot is deliberately allowed).
"""

import ast
from pathlib import Path

_INIT = (
    Path(__file__).resolve().parent.parent
    / "custom_components"
    / "alexa_media"
    / "__init__.py"
)


def _async_setup_entry_node() -> ast.AsyncFunctionDef:
    """Return the parsed ``async_setup_entry`` function node from ``__init__``."""
    tree = ast.parse(_INIT.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "async_setup_entry":
            return node
    raise AssertionError("async_setup_entry not found in __init__.py")


def _login_cookie_calls(scope: ast.AST) -> list[ast.Call]:
    """Collect every ``login.login(..., cookies=...)`` call within ``scope``."""
    calls = []
    for node in ast.walk(scope):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "login"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "login"
            and any(kw.arg == "cookies" for kw in node.keywords)
        ):
            calls.append(node)
    return calls


class TestCookieLoginNoInitBypass:
    """Guards forbidding the cookie-login init-bypass class in async_setup_entry."""

    def test_full_cookie_login_invoked_unconditionally(self):
        """``login.login(cookies=...)`` runs once, not behind a conditional skip.

        The bypass class hinged on guarding this call away (``if not
        cookie_login_ok:``). Requiring exactly one such call that is not nested
        under any conditional-skip construct (``if``/``while``/``for``/``match``)
        forbids reintroducing a shortcut that skips the real alexapy
        initialization. The outer ``try/except`` that wraps the whole boot is
        intentionally NOT treated as a skip construct: the legitimate call lives
        inside it, so ``ast.Try`` is excluded on purpose.
        """
        func = _async_setup_entry_node()
        calls = _login_cookie_calls(func)
        assert len(calls) == 1, (
            "expected exactly one login.login(cookies=...) call in "
            f"async_setup_entry, found {len(calls)}"
        )
        target = calls[0]
        skip_constructs = (ast.If, ast.While, ast.For, ast.AsyncFor, ast.match_case)
        for node in ast.walk(func):
            if isinstance(node, skip_constructs):
                assert target not in _login_cookie_calls(node), (
                    "login.login(cookies=...) is nested under a conditional-skip "
                    f"construct ({type(node).__name__}); the cookie-login init "
                    "bypass class was reintroduced"
                )

    def test_no_finalize_login_or_probe_markers(self):
        """No ``finalize_login``/``check_domain``/``cookie_login_ok`` markers.

        These attribute/name markers made up the bypass: ``finalize_login`` and
        ``check_domain`` finalized login without initialization, gated by the
        ``cookie_login_ok`` flag.
        """
        func = _async_setup_entry_node()
        attrs = {n.attr for n in ast.walk(func) if isinstance(n, ast.Attribute)}
        names = {n.id for n in ast.walk(func) if isinstance(n, ast.Name)}
        assert (
            "finalize_login" not in attrs
        ), "finalize_login call present in async_setup_entry; init bypass class"
        assert (
            "check_domain" not in attrs
        ), "check_domain call present in async_setup_entry; init bypass class"
        assert (
            "cookie_login_ok" not in names
        ), "cookie_login_ok flag present in async_setup_entry; init bypass class"

    def test_no_login_successful_flag_shortcut(self):
        """No ``login.status["login_successful"] = ...`` assignment shortcut.

        Setting the success flag directly (instead of letting ``login.login``
        set it after real initialization) is the marker of the bypass.
        """
        func = _async_setup_entry_node()
        for node in ast.walk(func):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Subscript) and isinstance(
                        target.slice, ast.Constant
                    ):
                        assert target.slice.value != "login_successful", (
                            'login.status["login_successful"] assignment present '
                            "in async_setup_entry; init bypass class"
                        )

    def test_no_hardcoded_bootstrap_probe_url(self):
        """No hardcoded ``.../api/bootstrap`` probe URL literal in the function.

        The removed probe hardcoded ``https://alexa.amazon.com/api/bootstrap``,
        which also ignored non-.com accounts. Its absence guards both the init
        bypass and the hardcoded-domain variant.
        """
        func = _async_setup_entry_node()
        literals = [
            n.value
            for n in ast.walk(func)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
        ]
        assert not any(
            "api/bootstrap" in literal for literal in literals
        ), "hardcoded /api/bootstrap probe URL present in async_setup_entry"
