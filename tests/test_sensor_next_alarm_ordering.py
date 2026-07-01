"""Regression tests for next-alarm selection vs. active-list ordering.

Covers the fork fix that keeps ``self._active[0]`` in sync with the selected
``self._next`` alarm. The desync (Codex round 2, finding 2) surfaced when a
stale/past ``ON`` alarm preceded a future active alarm: the sensor state showed
the future alarm while event firing and legacy label attributes still pointed at
the skipped past alarm, so Home Assistant state, automations, and attributes
diverged.

These tests pin the invariant ``self._active[0][1] is self._next`` for all
sensor types and assert that the event-firing path and legacy label attributes
agree with the sensor state.
"""

import datetime
from unittest.mock import MagicMock, patch

from custom_components.alexa_media.sensor import AlexaMediaNotificationSensor

UTC = datetime.timezone.utc
NOW = datetime.datetime(2024, 6, 1, 8, 0, 0, tzinfo=UTC)


def _make_sensor(sensor_type="Alarm"):
    """Return a bare notification sensor wired for the given type."""
    sensor = object.__new__(AlexaMediaNotificationSensor)
    sensor._type = sensor_type
    sensor._sensor_property = "date_time"
    sensor._debug = False
    sensor._account = "test@example.com"
    client = MagicMock()
    client._timezone = "UTC"
    client.device_serial_number = "serial1"
    sensor._client = client
    sensor._amz_id = None
    sensor._status = "OFF"
    sensor._version = None
    sensor._tracker = None
    sensor._attr_native_value = None
    sensor._prior_value = None
    sensor._next = None
    sensor._active = []
    sensor._all = []
    sensor._timestamp = None
    sensor._dismissed = None
    sensor.hass = MagicMock()
    sensor._n_dict = {}
    return sensor


def _alarm(alarm_id, when, status="ON"):
    """Build a raw alarm dict keyed for _n_dict ingestion."""
    return (
        alarm_id,
        {
            "id": alarm_id,
            "status": status,
            "date_time": when,
            "snoozedToTime": None,
            "type": "Alarm",
            "version": "1",
        },
    )


def _run_process(sensor):
    """Drive _process_raw_notifications with unrelated collaborators isolated."""
    with (
        patch("custom_components.alexa_media.sensor.dt.now", return_value=NOW),
        patch(
            "custom_components.alexa_media.sensor.alarm_just_dismissed",
            return_value=False,
        ),
        patch(
            "custom_components.alexa_media.sensor.async_track_point_in_utc_time",
            MagicMock(),
        ),
    ):
        sensor._process_raw_notifications()


class TestNextAlarmOrdering:
    """The selected next alarm must always be the head of self._active."""

    def test_stale_past_on_alarm_does_not_desync_state_and_event(self):
        """A past ON alarm before a future one must not desync _next/_active[0]."""
        past = NOW - datetime.timedelta(hours=2)
        future = NOW + datetime.timedelta(hours=1)
        sensor = _make_sensor("Alarm")
        # _n_dict ordering is irrelevant; _process sorts by date_time ascending,
        # so the past alarm would otherwise land at _active[0].
        sensor._n_dict = dict([_alarm("past", past), _alarm("future", future)])

        _run_process(sensor)

        # Invariant: container head matches the selected next alarm.
        assert sensor._active[0][1] is sensor._next
        # Sensor state reflects the future alarm...
        assert sensor._next["id"] == "future"
        # ...and the event-firing path emits the SAME alarm as the state.
        assert sensor._active[0][1]["id"] == "future"

    def test_legacy_label_matches_selected_next(self):
        """Legacy label attributes must point at the selected next alarm."""
        past = NOW - datetime.timedelta(hours=2)
        future = NOW + datetime.timedelta(hours=1)
        sensor = _make_sensor("Alarm")
        sensor._all = []
        sensor._n_dict = dict([_alarm("past", past), _alarm("future", future)])

        _run_process(sensor)
        attrs = sensor.extra_state_attributes

        # The first legacy/active entry is the selected next alarm.
        assert attrs["sorted_active"][0]["id"] == "future"
        assert attrs["sorted_active"][0]["id"] == sensor._next["id"]

    def test_single_future_alarm_stays_consistent(self):
        """The ordinary single-alarm case keeps the invariant (no regression)."""
        future = NOW + datetime.timedelta(hours=1)
        sensor = _make_sensor("Alarm")
        sensor._n_dict = dict([_alarm("only", future)])

        _run_process(sensor)

        assert sensor._active[0][1] is sensor._next
        assert sensor._next["id"] == "only"

    def test_non_alarm_type_invariant_holds(self):
        """Non-Alarm sensors keep _active[0][1] == _next via the existing path."""
        when = NOW + datetime.timedelta(minutes=30)
        sensor = _make_sensor("Timer")
        # Timers use the same active head as next; no reorder branch is taken.
        sensor._n_dict = dict(
            [
                (
                    "t1",
                    {
                        "id": "t1",
                        "status": "ON",
                        "date_time": when,
                        "snoozedToTime": None,
                        "type": "Timer",
                        "version": "1",
                    },
                )
            ]
        )

        _run_process(sensor)

        if sensor._active:
            assert sensor._active[0][1] is sensor._next

    def test_only_past_active_alarms_keep_head(self):
        """With no future alarm, the first past ON alarm stays the head."""
        older = NOW - datetime.timedelta(hours=3)
        newer_past = NOW - datetime.timedelta(hours=1)
        sensor = _make_sensor("Alarm")
        sensor._n_dict = dict(
            [_alarm("older", older), _alarm("newer_past", newer_past)]
        )

        _run_process(sensor)

        # _select_next_alarm falls back to _active[0]; no reorder is needed and
        # the invariant must still hold.
        assert sensor._active[0][1] is sensor._next
        assert sensor._next["id"] == "older"

    def test_reorder_preserves_other_active_alarms(self):
        """Promoting the selected alarm must keep the other active alarms."""
        soon = NOW + datetime.timedelta(minutes=30)
        later = NOW + datetime.timedelta(hours=2)
        past = NOW - datetime.timedelta(hours=1)
        sensor = _make_sensor("Alarm")
        sensor._n_dict = dict(
            [_alarm("past", past), _alarm("soon", soon), _alarm("later", later)]
        )

        _run_process(sensor)

        ids = [v["id"] for _, v in sensor._active]
        # Selected (earliest future) is the head; the identity filter drops only
        # that one object and keeps every other active alarm exactly once.
        assert sensor._active[0][1] is sensor._next
        assert sensor._next["id"] == "soon"
        assert sorted(ids) == ["later", "past", "soon"]
        assert len(ids) == len(set(ids))
