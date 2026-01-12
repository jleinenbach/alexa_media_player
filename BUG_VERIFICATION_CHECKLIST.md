# Bug-Verifikations-Checkliste für alexa_media_player

Diese Liste enthält alle behobenen Bugs in der alexa_media_player Integration.
Eine KI soll prüfen, ob diese Bugs korrekt behoben sind.

---

## Bug 1: timedelta JSON-Serialisierungsfehler

**Fehlermeldung:**
```
TypeError: Type is not JSON serializable: datetime.timedelta
```

**Ursache:** `datetime.timedelta`-Objekte wurden in `config_entry.data` gespeichert.

**Betroffene Dateien:**
- `custom_components/alexa_media/__init__.py`
- `custom_components/alexa_media/config_flow.py`

**Prüfpunkte:**

1. **Migration in `async_setup_entry`** (`__init__.py`, ca. Zeile 237-249):
   - [ ] Es existiert Code, der `config_entry.data` auf `timedelta`-Werte prüft
   - [ ] `timedelta`-Werte werden mit `.total_seconds()` zu `float` konvertiert
   - [ ] Nach der Konvertierung wird `async_update_entry()` aufgerufen

2. **OAuth-Update Sanitisierung** (`__init__.py`, ca. Zeile 710-720):
   - [ ] Vor `async_update_entry()` werden Daten sanitisiert
   - [ ] Dict-Comprehension mit `isinstance(v, timedelta)` Check existiert

3. **OptionsFlowHandler** (`config_flow.py`, ca. Zeile 986-993):
   - [ ] `user_input` wird vor `async_update_entry()` sanitisiert
   - [ ] `sanitized_input` Variable mit timedelta-Konvertierung existiert

**Regressionstests:** `tests/test_timedelta_migration.py`

---

## Bug 2: Reauth löst keinen Integration-Reload aus

**Problem:** Nach erfolgreicher Reauthentifizierung blieb die Integration im Fehlerzustand.

**Betroffene Datei:** `custom_components/alexa_media/config_flow.py`

**Prüfpunkte:**

1. **In `_test_login()` Methode** (ca. Zeile 650-660):
   - [ ] Nach `async_update_entry()` für existierende Einträge wird `async_reload()` aufgerufen
   - [ ] `async_reload(existing_entry.entry_id)` wird mit der Entry-ID aufgerufen
   - [ ] `async_abort(reason="reauth_successful")` wird aufgerufen

2. **Neue Einträge lösen KEINEN Reload aus:**
   - [ ] `async_reload()` wird NUR bei Reauth aufgerufen, nicht bei neuen Einträgen

**Regressionstests:** `tests/test_config_flow.py::TestReauthReload`

---

## Bug 3: IndexError bei entry_id.split("#")

**Problem:** `entry_id.split("#")[2]` warf `IndexError` wenn weniger als 3 Teile vorhanden.

**Betroffene Datei:** `custom_components/alexa_media/__init__.py`

**Prüfpunkte:**

1. **Sicherheitscheck vor Array-Zugriff:**
   - [ ] `len(parts) > 2` Check existiert VOR Zugriff auf `parts[2]`
   - [ ] Pattern: `parts[2] if len(parts) > 2 else None` oder ähnlich
   - [ ] Kein direkter `split("#")[2]` Zugriff ohne Längenprüfung

**Regressionstests:** `tests/test_init_split.py::TestEntryIdSplit`

---

## Bug 4: IndexError bei appliance_id.split("_")

**Problem:** `appliance_id.split("_")[2]` warf `IndexError` bei IDs mit weniger als 3 Teilen.

**Betroffene Datei:** `custom_components/alexa_media/alarm_control_panel.py`

**Prüfpunkte:**

1. **Sicherheitscheck vor Array-Zugriff:**
   - [ ] `len(appliance_parts) > 2` Check existiert
   - [ ] Pattern: `appliance_parts[2] if len(appliance_parts) > 2 else appliance_id`
   - [ ] Fallback auf Original-ID wenn nicht genug Teile

**Regressionstests:** `tests/test_alarm_control_panel.py::TestApplianceIdSplit`

---

## Bug 5: KeyError in notify.py devices Property

**Problem:** `"and"` statt `"or"` führte zu KeyError wenn `accounts` Key fehlte.

**Betroffene Datei:** `custom_components/alexa_media/notify.py`

**Prüfpunkte:**

1. **In `devices` Property der `AlexaNotificationService` Klasse:**
   - [ ] Early Return wenn `DATA_ALEXAMEDIA` nicht in `hass.data`
   - [ ] Early Return wenn `"accounts"` nicht in `hass.data[DATA_ALEXAMEDIA]`
   - [ ] Verwendung von `or` für Short-Circuit-Evaluation (NICHT `and`)

**Regressionstests:** `tests/test_notify.py::TestAlexaNotificationServiceDevices`

---

## Bug 6: IndexError in sensor._trigger_event bei leerer _active Liste

**Problem:** Zugriff auf `self._active[0]` ohne Prüfung ob Liste leer ist.

**Betroffene Datei:** `custom_components/alexa_media/sensor.py`

**Prüfpunkte:**

1. **In `_trigger_event` Methode der `AlexaMediaNotificationSensor` Klasse:**
   - [ ] Check ob `self._active` leer ist BEVOR Zugriff auf `self._active[0]`
   - [ ] Early Return wenn `not self._active` oder `len(self._active) == 0`
   - [ ] `hass.bus.fire()` wird NUR aufgerufen wenn `_active` nicht leer

**Regressionstests:** `tests/test_sensor.py::TestTriggerEvent`

---

## Bug 7: sensor.async_unload_entry iteriert falsch über sensors

**Problem:** Iteration über `sensors` statt `sensors.values()`.

**Betroffene Datei:** `custom_components/alexa_media/sensor.py`

**Prüfpunkte:**

1. **In `async_unload_entry` Funktion:**
   - [ ] Korrekte Iteration über verschachtelte Sensor-Struktur
   - [ ] Zugriff auf `sensor.async_remove()` für jeden Sensor
   - [ ] Fehlerbehandlung wenn `async_remove` nicht existiert

**Regressionstests:** `tests/test_sensor.py::TestAsyncUnloadEntry`

---

## Bug 8: safe_get escaped keine Punkte in Keys

**Problem:** Keys mit Punkten (z.B. `"user.email"`) wurden nicht korrekt escaped.

**Betroffene Datei:** `custom_components/alexa_media/helpers.py`

**Prüfpunkte:**

1. **In `safe_get` Funktion:**
   - [ ] Punkte in Key-Namen werden mit `\\.` escaped
   - [ ] Path-Segmente werden mit `.` verbunden
   - [ ] Integer-Segmente werden zu Strings konvertiert
   - [ ] `pathsep` Kwarg wird entfernt bevor `dictor` aufgerufen wird

**Regressionstests:** `tests/test_helpers.py::test_safe_get_*`

---

## Bug 9: safe_get Typ-Mismatch Handling

**Problem:** Kein Typ-Check zwischen Rückgabewert und Default-Wert.

**Betroffene Datei:** `custom_components/alexa_media/helpers.py`

**Prüfpunkte:**

1. **In `safe_get` Funktion:**
   - [ ] Wenn Default angegeben und nicht None: `isinstance(result, type(default))` Check
   - [ ] Bei Typ-Mismatch wird Default zurückgegeben
   - [ ] None-Ergebnisse werden durchgelassen (kein Typ-Check)
   - [ ] Ohne Default kein Typ-Check

**Regressionstests:** `tests/test_helpers.py::test_safe_get_type_*`

---

## Zusammenfassung der Test-Dateien

| Bug | Test-Datei | Test-Klasse/Funktion |
|-----|------------|---------------------|
| 1 | `test_timedelta_migration.py` | `TestTimedeltaSanitization`, `TestConfigDataJsonSerializable`, `TestOptionsFlowSanitizationLogic`, `TestMigrationLogic` |
| 2 | `test_config_flow.py` | `TestReauthReload` |
| 3 | `test_init_split.py` | `TestEntryIdSplit` |
| 4 | `test_alarm_control_panel.py` | `TestApplianceIdSplit` |
| 5 | `test_notify.py` | `TestAlexaNotificationServiceDevices` |
| 6 | `test_sensor.py` | `TestTriggerEvent` |
| 7 | `test_sensor.py` | `TestAsyncUnloadEntry` |
| 8-9 | `test_helpers.py` | `test_safe_get_*` |

---

## Verifikations-Befehle

```bash
# Alle Tests ausführen
python3.13 -m pytest tests/ -v

# Spezifische Bug-Tests ausführen
python3.13 -m pytest tests/test_timedelta_migration.py -v  # Bug 1
python3.13 -m pytest tests/test_config_flow.py -v          # Bug 2
python3.13 -m pytest tests/test_init_split.py -v           # Bug 3
python3.13 -m pytest tests/test_alarm_control_panel.py -v  # Bug 4
python3.13 -m pytest tests/test_notify.py -v               # Bug 5
python3.13 -m pytest tests/test_sensor.py -v               # Bug 6, 7
python3.13 -m pytest tests/test_helpers.py -v              # Bug 8, 9

# Code-Qualität prüfen
python3.13 -m mypy --strict --ignore-missing-imports custom_components/alexa_media/
python3.13 -m ruff check custom_components/alexa_media/
python3.13 -m ruff format --check custom_components/alexa_media/
```

---

## Erwartetes Ergebnis

Alle 129 Tests sollten bestehen:
```
======================== 129 passed, 1 warning ========================
```
