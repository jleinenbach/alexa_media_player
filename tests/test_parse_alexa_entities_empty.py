"""Characterization tests for ``parse_alexa_entities`` on empty/``None`` input.

These tests pin down *why* the network-discovery guard fix matters: when Alexa
returns no network details, ``parse_alexa_entities`` does not raise or return
``None`` but yields a dict whose seven entity buckets are all empty lists. A
``devices.update(...)`` with that result therefore silently overwrites a
previously stored discovery snapshot with empties. Guarding the call behind the
success branch is the fix; these tests document the destructive premise it
removes. They exercise ``parse_alexa_entities`` without the full Home Assistant
config-entry harness (Tier 2); the package's declared ``alexapy`` dependency,
present in CI, is the only import requirement.
"""

import pytest

from custom_components.alexa_media.alexa_entity import parse_alexa_entities

# The seven buckets returned by the early-return branch (alexa_entity.py).
_EXPECTED_KEYS = {
    "light",
    "guard",
    "temperature",
    "air_quality",
    "aiaqm",
    "binary_sensor",
    "smart_switch",
}


@pytest.mark.parametrize("empty_input", [None, []])
def test_parse_returns_all_buckets_empty(empty_input):
    """``None``/empty input yields every bucket present but empty.

    This is the exact shape that makes ``devices.update(result)`` destructive:
    each stored key is overwritten with an empty list rather than left intact.
    """
    result = parse_alexa_entities(empty_input)

    assert set(result) == _EXPECTED_KEYS
    assert all(result[key] == [] for key in _EXPECTED_KEYS)


def test_update_with_empty_result_clobbers_existing_snapshot():
    """``dict.update`` with the empty parse result wipes a prior snapshot.

    Models the production call ``devices.update(parse_alexa_entities(...))`` to
    show that, without the guard, a transient empty Alexa response erases the
    extended entities that a previous successful discovery had stored.
    """
    stored = {
        "guard": [{"id": "guard-1"}],
        "temperature": [{"id": "temp-1"}],
        "light": [{"id": "light-1"}],
    }

    stored.update(parse_alexa_entities(None))

    assert stored["guard"] == []
    assert stored["temperature"] == []
    assert stored["light"] == []
