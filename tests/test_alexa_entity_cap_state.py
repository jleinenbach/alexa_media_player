"""Regression tests for ``is_cap_state_still_acceptable``.

This guards a fork-relevant correctness fix. Upstream switched the
``timeOfSample`` parser to ``datetime.fromisoformat()`` (PR #3360), which,
unlike the previous ``%z`` parser, accepts an offset-less (naive) timestamp.
Comparing that naive value with the timezone-aware ``since`` raised
``TypeError`` and aborted coordinator state parsing. The fix rejects naive
parsed values and widens the parse guard to ``TypeError`` so that non-string
``timeOfSample`` values are treated as unusable as well.

Invariant verified at the call site (``parse_value_from_coordinator`` ->
light.py / switch.py): ``since`` is either ``None`` or an aware
``datetime.now(timezone.utc)``.
"""

from datetime import datetime, timedelta, timezone

from custom_components.alexa_media.alexa_entity import is_cap_state_still_acceptable


def _aware_now() -> datetime:
    """Return an aware ``now`` in UTC (mirrors the call-site invariant)."""
    return datetime.now(timezone.utc)


class TestIsCapStateStillAcceptable:
    """Behavioural tests for the requested-state freshness guard."""

    def test_since_none_returns_true(self):
        """No requested state -> any coordinator value is acceptable."""
        assert is_cap_state_still_acceptable({}, None) is True

    def test_ttl_exceeded_returns_true(self):
        """Past the TTL the coordinator wins even without a usable sample."""
        old_since = _aware_now() - timedelta(seconds=120)
        assert is_cap_state_still_acceptable({}, old_since) is True

    def test_missing_time_of_sample_returns_false(self):
        """Within TTL and no sample -> cannot prove freshness, reject."""
        fresh_since = _aware_now() - timedelta(seconds=1)
        assert is_cap_state_still_acceptable({}, fresh_since) is False

    def test_naive_time_of_sample_returns_false_without_typeerror(self):
        """Naive timestamp must be rejected, not crash the comparison.

        This is the core regression: ``datetime.fromisoformat`` accepts the
        offset-less string, and comparing it with the aware ``since`` would
        raise ``TypeError`` without the naive guard.
        """
        fresh_since = _aware_now() - timedelta(seconds=1)
        cap_state = {"timeOfSample": "2026-06-30T10:00:00"}  # no offset
        assert is_cap_state_still_acceptable(cap_state, fresh_since) is False

    def test_non_string_time_of_sample_returns_false(self):
        """Non-string (truthy) timeOfSample -> TypeError path -> reject.

        Covers the widened ``except (ValueError, TypeError)`` guard.
        """
        fresh_since = _aware_now() - timedelta(seconds=1)
        cap_state = {"timeOfSample": 1717146000}  # int, passes the truthy gate
        assert is_cap_state_still_acceptable(cap_state, fresh_since) is False

    def test_unparsable_time_of_sample_returns_false(self):
        """Unparsable string -> ValueError path -> reject."""
        fresh_since = _aware_now() - timedelta(seconds=1)
        cap_state = {"timeOfSample": "not-a-timestamp"}
        assert is_cap_state_still_acceptable(cap_state, fresh_since) is False

    def test_aware_sample_newer_than_since_returns_true(self):
        """Aware sample newer than ``since`` -> acceptable (unchanged path)."""
        since = _aware_now() - timedelta(seconds=2)
        sample = _aware_now()
        cap_state = {"timeOfSample": sample.isoformat()}
        assert is_cap_state_still_acceptable(cap_state, since) is True

    def test_aware_sample_older_than_since_returns_false(self):
        """Aware sample older than ``since`` -> rejected (unchanged path)."""
        since = _aware_now()
        sample = since - timedelta(seconds=5)
        cap_state = {"timeOfSample": sample.isoformat()}
        assert is_cap_state_still_acceptable(cap_state, since) is False
