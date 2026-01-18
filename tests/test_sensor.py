"""Tests for sensor module.

Tests the sensor functionality using pytest-homeassistant-custom-component.
"""

import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.alexa_media.const import DATA_ALEXAMEDIA


class TestAsyncUnloadEntry:
    """Test the async_unload_entry function."""

    @pytest.mark.asyncio
    async def test_async_unload_entry_with_sensors(self):
        """Test unloading sensors iterates over sensors.values() correctly."""
        from custom_components.alexa_media.sensor import async_unload_entry

        hass = MagicMock()
        entry = MagicMock()
        entry.data = {"email": "test@example.com"}

        # Create mock sensors with async_remove method (must be AsyncMock)
        mock_sensor1 = MagicMock()
        mock_sensor1.async_remove = AsyncMock()

        mock_sensor2 = MagicMock()
        mock_sensor2.async_remove = AsyncMock()

        # Structure: account_dict["entities"]["sensor"][device_serial][sensor_type] = sensor
        hass.data = {
            DATA_ALEXAMEDIA: {
                "accounts": {
                    "test@example.com": {
                        "entities": {
                            "sensor": {
                                "device_serial_1": {
                                    "Alarm": mock_sensor1,
                                    "Timer": mock_sensor2,
                                }
                            }
                        }
                    }
                }
            }
        }

        result = await async_unload_entry(hass, entry)

        assert result is True
        mock_sensor1.async_remove.assert_called_once()
        mock_sensor2.async_remove.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_unload_entry_empty_sensors(self):
        """Test unloading when no sensors exist."""
        from custom_components.alexa_media.sensor import async_unload_entry

        hass = MagicMock()
        entry = MagicMock()
        entry.data = {"email": "test@example.com"}

        hass.data = {
            DATA_ALEXAMEDIA: {
                "accounts": {"test@example.com": {"entities": {"sensor": {}}}}
            }
        }

        result = await async_unload_entry(hass, entry)
        assert result is True

    @pytest.mark.asyncio
    async def test_async_unload_entry_sensor_without_async_remove(self):
        """Test unloading sensors that don't have async_remove method."""
        from custom_components.alexa_media.sensor import async_unload_entry

        hass = MagicMock()
        entry = MagicMock()
        entry.data = {"email": "test@example.com"}

        # Create a mock sensor without async_remove attribute
        mock_sensor = MagicMock(spec=[])  # Empty spec = no attributes

        hass.data = {
            DATA_ALEXAMEDIA: {
                "accounts": {
                    "test@example.com": {
                        "entities": {
                            "sensor": {
                                "device_serial_1": {
                                    "Alarm": mock_sensor,
                                }
                            }
                        }
                    }
                }
            }
        }

        # Should not raise, just skip the sensor
        result = await async_unload_entry(hass, entry)
        assert result is True


class TestTriggerEvent:
    """Test the _trigger_event method of AlexaMediaNotificationSensor."""

    def test_trigger_event_with_empty_active_list(self):
        """Test that _trigger_event handles empty _active list gracefully."""
        from custom_components.alexa_media.sensor import AlexaMediaNotificationSensor

        # Create a minimal mock for the sensor
        sensor = object.__new__(AlexaMediaNotificationSensor)
        sensor._active = []  # Empty list - the race condition case
        sensor._account = "test@example.com"
        sensor.hass = MagicMock()

        # Should not raise IndexError
        sensor._trigger_event(MagicMock())

        # bus.fire should NOT be called when _active is empty
        sensor.hass.bus.fire.assert_not_called()

    def test_trigger_event_with_active_notifications(self):
        """Test that _trigger_event fires event when _active has items."""
        from custom_components.alexa_media.sensor import AlexaMediaNotificationSensor

        # Create a minimal mock for the sensor
        sensor = object.__new__(AlexaMediaNotificationSensor)
        sensor._active = [("id1", {"id": "notification1", "status": "ON"})]
        sensor._account = "test@example.com"
        sensor.name = "Test Sensor"
        sensor.entity_id = "sensor.test_sensor"
        sensor.hass = MagicMock()

        mock_time = MagicMock()
        sensor._trigger_event(mock_time)

        # bus.fire should be called
        sensor.hass.bus.fire.assert_called_once()
        call_args = sensor.hass.bus.fire.call_args
        assert call_args[0][0] == "alexa_media_notification_event"
        assert call_args[1]["event_data"]["event"] == sensor._active[0]

from custom_components.alexa_media.sensor import AlexaMediaNotificationSensor


class TestUpdateRecurringAlarm:
    """Test the _update_recurring_alarm method of AlexaMediaNotificationSensor.

    This class tests the fix for a critical bug where alarm.isoweekday was used
    instead of alarm.isoweekday() - missing the parentheses to actually call the
    method. Without the parentheses, the condition would compare a method object
    to integers, which would always be True, causing incorrect alarm scheduling.
    """

    def test_isoweekday_method_is_called_correctly(self) -> None:
        """Test that isoweekday() is called as a method, not accessed as attribute.

        This is a regression test for a bug where alarm.isoweekday was used instead
        of alarm.isoweekday(). Without the parentheses, a method object would be
        compared to integers in the recurrence set, which would never match,
        causing the while loop to run indefinitely or produce wrong results.

        The bug would manifest when:
        - An alarm is set to ON
        - The alarm has a recurring pattern (e.g., "every Monday")
        - The current alarm time is in the past
        - The current alarm day doesn't match the recurrence pattern

        With the bug, the condition `alarm.isoweekday not in recurrence` would
        always be True (method object never equals an integer), potentially
        causing infinite loops or incorrect alarm times.
        """
        # Create a minimal mock for the sensor
        sensor = object.__new__(AlexaMediaNotificationSensor)
        sensor._sensor_property = "alarmTime"

        # Create a datetime that is a Wednesday (isoweekday() == 3)
        # and set it in the past so the while loop condition is met
        wednesday_in_past = datetime.datetime(2024, 1, 3, 8, 0, 0)  # Wednesday
        assert wednesday_in_past.isoweekday() == 3  # Verify it's Wednesday

        # Create recurrence that only allows Fridays (isoweekday 5)
        # This means the alarm should advance to the next Friday
        recurrence_fridays_only = {5}

        # Create the alarm notification data
        value = (
            "alarm_id",
            {
                "status": "ON",
                "alarmTime": wednesday_in_past,
                "type": "Alarm",
                "recurringPattern": "XXXX-WXX-5",  # Every Friday
            },
        )

        # Mock dt.now() to return a time after the alarm
        # so the condition `alarm < dt.now()` is True
        future_time = datetime.datetime(2024, 1, 10, 8, 0, 0)

        with (
            patch(
                "custom_components.alexa_media.sensor.dt.now", return_value=future_time
            ),
            patch(
                "custom_components.alexa_media.sensor.RECURRING_PATTERN_ISO_SET",
                {"XXXX-WXX-5": recurrence_fridays_only},
            ),
        ):
            result = sensor._update_recurring_alarm(value)

        # The alarm should have been advanced from Wednesday (Jan 3)
        # to Friday (Jan 5) since only Fridays are in the recurrence
        result_alarm = result[1]["alarmTime"]

        # With the fix: isoweekday() returns 3, which is not in {5},
        # so days are added until isoweekday() returns 5 (Friday)
        assert result_alarm.isoweekday() == 5, (
            f"Alarm should be on Friday (isoweekday 5), "
            f"but got isoweekday {result_alarm.isoweekday()}"
        )

        # Verify the alarm moved forward (not backward)
        assert result_alarm >= wednesday_in_past

    def test_recurring_alarm_advances_to_correct_weekday(self) -> None:
        """Test that a recurring alarm advances to the correct weekday."""
        sensor = object.__new__(AlexaMediaNotificationSensor)
        sensor._sensor_property = "alarmTime"

        # Monday January 1, 2024
        monday = datetime.datetime(2024, 1, 1, 8, 0, 0)
        assert monday.isoweekday() == 1

        # Recurrence only on weekends (Saturday=6, Sunday=7)
        weekend_recurrence = {6, 7}

        value = (
            "alarm_id",
            {
                "status": "ON",
                "alarmTime": monday,
                "type": "Alarm",
                "recurringPattern": "XXXX-WE",  # Weekends
            },
        )

        future_time = datetime.datetime(2024, 1, 10, 8, 0, 0)

        with (
            patch(
                "custom_components.alexa_media.sensor.dt.now", return_value=future_time
            ),
            patch(
                "custom_components.alexa_media.sensor.RECURRING_PATTERN_ISO_SET",
                {"XXXX-WE": weekend_recurrence},
            ),
        ):
            result = sensor._update_recurring_alarm(value)

        result_alarm = result[1]["alarmTime"]

        # Should advance to Saturday (Jan 6, 2024)
        assert result_alarm.isoweekday() in {
            6,
            7,
        }, f"Alarm should be on weekend, but got isoweekday {result_alarm.isoweekday()}"
        assert result_alarm == datetime.datetime(2024, 1, 6, 8, 0, 0)

    def test_alarm_on_correct_day_not_modified(self) -> None:
        """Test that an alarm already on a correct day is not modified."""
        sensor = object.__new__(AlexaMediaNotificationSensor)
        sensor._sensor_property = "alarmTime"

        # Friday January 5, 2024
        friday = datetime.datetime(2024, 1, 5, 8, 0, 0)
        assert friday.isoweekday() == 5

        # Recurrence includes Friday
        recurrence_with_friday = {5}

        value = (
            "alarm_id",
            {
                "status": "ON",
                "alarmTime": friday,
                "type": "Alarm",
                "recurringPattern": "XXXX-WXX-5",
            },
        )

        # Even with future time, alarm should not advance if it's already on correct day
        # Note: the loop only runs if alarm < dt.now(), so if alarm is in the past
        # but on correct day, it won't advance
        past_time = datetime.datetime(2024, 1, 4, 8, 0, 0)  # Thursday before alarm

        with (
            patch(
                "custom_components.alexa_media.sensor.dt.now", return_value=past_time
            ),
            patch(
                "custom_components.alexa_media.sensor.RECURRING_PATTERN_ISO_SET",
                {"XXXX-WXX-5": recurrence_with_friday},
            ),
        ):
            result = sensor._update_recurring_alarm(value)

        # Alarm should not be modified since it's in the future relative to now
        assert result[1]["alarmTime"] == friday

    def test_alarm_off_not_advanced(self) -> None:
        """Test that an alarm with status OFF is not advanced."""
        sensor = object.__new__(AlexaMediaNotificationSensor)
        sensor._sensor_property = "alarmTime"

        wednesday = datetime.datetime(2024, 1, 3, 8, 0, 0)

        value = (
            "alarm_id",
            {
                "status": "OFF",  # Alarm is OFF
                "alarmTime": wednesday,
                "type": "Alarm",
                "recurringPattern": "XXXX-WXX-5",
            },
        )

        future_time = datetime.datetime(2024, 1, 10, 8, 0, 0)

        with (
            patch(
                "custom_components.alexa_media.sensor.dt.now", return_value=future_time
            ),
            patch(
                "custom_components.alexa_media.sensor.RECURRING_PATTERN_ISO_SET",
                {"XXXX-WXX-5": {5}},
            ),
        ):
            result = sensor._update_recurring_alarm(value)

        # Alarm should NOT be advanced since status is OFF
        assert result[1]["alarmTime"] == wednesday

    def test_alarm_without_recurrence_not_modified(self) -> None:
        """Test that an alarm without recurring pattern is not modified."""
        sensor = object.__new__(AlexaMediaNotificationSensor)
        sensor._sensor_property = "alarmTime"

        wednesday = datetime.datetime(2024, 1, 3, 8, 0, 0)

        value = (
            "alarm_id",
            {
                "status": "ON",
                "alarmTime": wednesday,
                "type": "Alarm",
                # No recurringPattern
            },
        )

        future_time = datetime.datetime(2024, 1, 10, 8, 0, 0)

        with patch(
            "custom_components.alexa_media.sensor.dt.now", return_value=future_time
        ):
            result = sensor._update_recurring_alarm(value)

        # Alarm should NOT be advanced since there's no recurrence pattern
        assert result[1]["alarmTime"] == wednesday

    def test_reminder_type_handled(self) -> None:
        """Test that reminder type alarms are handled correctly."""
        sensor = object.__new__(AlexaMediaNotificationSensor)
        sensor._sensor_property = "alarmTime"  # Reminders also use alarmTime

        wednesday = datetime.datetime(2024, 1, 3, 8, 0, 0)

        value = (
            "reminder_id",
            {
                "status": "ON",
                "alarmTime": wednesday,
                "type": "Reminder",
                "recurringPattern": "XXXX-WXX-5",
            },
        )

        future_time = datetime.datetime(2024, 1, 10, 8, 0, 0)

        with (
            patch(
                "custom_components.alexa_media.sensor.dt.now", return_value=future_time
            ),
            patch(
                "custom_components.alexa_media.sensor.RECURRING_PATTERN_ISO_SET",
                {"XXXX-WXX-5": {5}},
            ),
        ):
            result = sensor._update_recurring_alarm(value)

        result_alarm = result[1]["alarmTime"]
        # Reminders should also be advanced correctly
        assert result_alarm.isoweekday() == 5
