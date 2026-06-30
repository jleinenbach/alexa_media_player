"""Regression anchors for fork-specific setup ordering (PR #21).

The fork deliberately primes ``update_last_called`` *synchronously* before the
coordinator's first refresh, and dropped the upstream background last_called
task to avoid a double fetch. An upstream sync silently broke exactly this
class once already, so these anchors guard the two structural invariants:

1. the dropped ``_async_update_last_called_background`` wrapper must stay gone
   (its reintroduction is the double-fetch regression), and
2. inside ``async_setup_entry`` the synchronous ``update_last_called`` priming
   must still precede ``async_config_entry_first_refresh``.

These are source-structure assertions on purpose: the surrounding
``async_setup_entry`` is only reachable through a full Home Assistant
config-entry harness, which is out of scope here (declared coverage exception,
Tier 3). The runtime behaviour stays CI-authoritative.
"""

from pathlib import Path

_INIT = (
    Path(__file__).resolve().parent.parent
    / "custom_components"
    / "alexa_media"
    / "__init__.py"
)


def _init_source() -> str:
    return _INIT.read_text(encoding="utf-8")


class TestSetupOrderingAnchors:
    """Structural regression guards for the PR #21 setup ordering."""

    def test_background_double_fetch_wrapper_not_reintroduced(self):
        """The upstream background last_called wrapper must stay removed."""
        assert "_async_update_last_called_background" not in _init_source()

    def test_last_called_primed_before_first_refresh(self):
        """Synchronous update_last_called must precede the first refresh.

        Compared by source index rather than a fixed line window, so a benign
        refactor that adds lines between priming and refresh does not raise a
        false alarm; only an actual order reversal fails the test.
        """
        lines = _init_source().splitlines()
        prime_indices = [
            i
            for i, line in enumerate(lines)
            if "await update_last_called(login_obj)" in line
        ]
        refresh_indices = [
            i
            for i, line in enumerate(lines)
            if "async_config_entry_first_refresh()" in line
        ]
        assert prime_indices, "synchronous update_last_called priming not found"
        assert refresh_indices, "first-refresh call not found in async_setup_entry"

        assert min(prime_indices) < min(
            refresh_indices
        ), "synchronous update_last_called priming no longer precedes first refresh"
