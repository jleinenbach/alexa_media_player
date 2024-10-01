"""
Alexa Config Flow.

SPDX-License-Identifier: Apache-2.0

For more details about this platform, please refer to the documentation at
https://community.home-assistant.io/t/echo-devices-alexa-as-media-player-testers-needed/58639
"""

# Standard library imports
import asyncio
import datetime
from datetime import timedelta
from functools import reduce
import logging
from typing import Any, Optional
import urllib.parse

# Third-party library imports
from aiohttp import ClientConnectionError, ClientSession, web
from aiohttp.web_exceptions import HTTPBadRequest
import voluptuous as vol
from yarl import URL
import idna  # For domain validation, including internationalized domain names (IDNs)

# alexapy imports for Alexa interactions
from alexapy import (
    AlexaLogin,
    AlexaProxy,
    AlexapyConnectionError,
    AlexapyPyotpInvalidKey,
    __version__ as alexapy_version,
    hide_email,
    obfuscate,
)

# Home Assistant core and helpers imports
from homeassistant import config_entries
from homeassistant.components.http.view import HomeAssistantView
from homeassistant.components.persistent_notification import (
    async_dismiss as async_dismiss_persistent_notification,
)
from homeassistant.const import (
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_URL,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import AbortFlow, FlowResult, UnknownFlow
from homeassistant.exceptions import Unauthorized, HomeAssistantError
from homeassistant.helpers import config_validation as cv, translation
from homeassistant.helpers.network import NoURLAvailableError, get_url
from homeassistant.helpers.selector import (
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
    NumberSelector,
    NumberSelectorConfig,
    BooleanSelector,
    BooleanSelectorConfig,
)
from homeassistant.helpers.typing import ConfigType
from homeassistant.util import slugify

# Local application/component specific imports
from .const import (
    AUTH_CALLBACK_NAME,
    AUTH_CALLBACK_PATH,
    AUTH_PROXY_NAME,
    AUTH_PROXY_PATH,
    CONF_DEBUG,
    CONF_EXCLUDE_DEVICES,
    CONF_EXTENDED_ENTITY_DISCOVERY,
    CONF_HASS_URL,
    CONF_INCLUDE_DEVICES,
    CONF_OAUTH,
    CONF_OTPSECRET,
    CONF_PROXY_WARNING,
    CONF_PUBLIC_URL,
    CONF_QUEUE_DELAY,
    CONF_SECURITYCODE,
    CONF_TOTP_REGISTER,
    DATA_ALEXAMEDIA,
    DEFAULT_DEBUG,
    DEFAULT_EXTENDED_ENTITY_DISCOVERY,
    DEFAULT_HASS_URL,
    DEFAULT_PUBLIC_URL,
    DEFAULT_QUEUE_DELAY,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    ISSUE_URL,
    STARTUP,
)
from .helpers import calculate_uuid

_LOGGER = logging.getLogger(__name__)

CONFIG_VERSION = 1


def is_valid_domain(domain: str) -> bool:
    """
    Validate if the input is a valid domain using idna.

    Args:
        domain (str): The domain name to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    try:
        # Attempt to encode the domain using idna
        idna.encode(domain)
        return True
    except idna.IDNAError as e:
        _LOGGER.warning("Invalid domain '%s' entered: %s", domain, str(e))
        return False



@callback
def configured_instances(hass: HomeAssistant) -> set:
    """Return a set of configured Alexa Media instances."""
    return {entry.title for entry in hass.config_entries.async_entries(DOMAIN)}


@callback
def in_progress_instances(hass: HomeAssistant) -> set:
    """Return a set of in-progress Alexa Media flows."""
    return {
        entry["flow_id"]
        for entry in hass.config_entries.flow.async_progress()
        if entry["handler"] == DOMAIN
    }



class AlexaMediaFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """
    Handle a Alexa Media config flow.
    
    async_external_step and async_external_step_done are methods from the
    Home Assistant Core Config Flow framework.
    They manage external authentication steps and should not be confused
    with custom-defined methods.
    """

    VERSION = CONFIG_VERSION
    CONNECTION_CLASS = config_entries.CONN_CLASS_CLOUD_POLL

    def _save_user_input_to_config(self, user_input: Optional[dict[str, Any]] = None) -> None:
        """Process user_input to save to self.config."""
        if user_input is None:
            return

        # Update HASS URL if provided
        if CONF_HASS_URL in user_input:
            self.config[CONF_HASS_URL] = user_input[CONF_HASS_URL]

        # Update security code if provided
        self.securitycode = user_input.get(CONF_SECURITYCODE)
        if self.securitycode is not None:
            self.config[CONF_SECURITYCODE] = self.securitycode
        elif CONF_SECURITYCODE in self.config:
            self.config.pop(CONF_SECURITYCODE)

        # Update OTP secret if provided; retain existing if not provided
        otp_secret = user_input.get(CONF_OTPSECRET)
        if otp_secret and otp_secret.strip():
            self.config[CONF_OTPSECRET] = otp_secret.replace(" ", "")
        # Else, if not provided, retain existing OTP secret (do nothing)

        # Update email if provided
        if CONF_EMAIL in user_input:
            self.config[CONF_EMAIL] = user_input[CONF_EMAIL]

        # Update password if provided; retain existing if not provided
        password = user_input.get(CONF_PASSWORD)
        if password:
            self.config[CONF_PASSWORD] = password
        elif CONF_PASSWORD not in self.config:
            # Password is required if not already stored
            raise vol.Invalid("Password is required.")
        # If password is not provided but exists in config, retain it

        # Validate and save the domain URL (e.g., amazon.com)
        if CONF_URL in user_input:
            domain = user_input[CONF_URL]
            if not is_valid_domain(domain):
                raise vol.Invalid("Please enter a valid domain (e.g., amazon.com).")
            else:
                self.config[CONF_URL] = domain

        # Update public URL if provided
        if CONF_PUBLIC_URL in user_input:
            self.config[CONF_PUBLIC_URL] = user_input[CONF_PUBLIC_URL]

        # Update scan interval if provided
        if CONF_SCAN_INTERVAL in user_input:
            scan_interval = user_input[CONF_SCAN_INTERVAL]
            if isinstance(scan_interval, timedelta):
                self.config[CONF_SCAN_INTERVAL] = scan_interval.total_seconds()
            else:
                self.config[CONF_SCAN_INTERVAL] = scan_interval

        # Update queue delay if provided
        if CONF_QUEUE_DELAY in user_input:
            self.config[CONF_QUEUE_DELAY] = user_input[CONF_QUEUE_DELAY]

        # Update included devices if provided
        if CONF_INCLUDE_DEVICES in user_input:
            include_devices_str = user_input[CONF_INCLUDE_DEVICES]
            if not include_devices_str.strip():
                self.config[CONF_INCLUDE_DEVICES] = []
            else:
                self.config[CONF_INCLUDE_DEVICES] = [
                    device.strip() for device in include_devices_str.split(",") if device.strip()
                ]

        # Update excluded devices if provided
        if CONF_EXCLUDE_DEVICES in user_input:
            exclude_devices_str = user_input[CONF_EXCLUDE_DEVICES]
            if not exclude_devices_str.strip():
                self.config[CONF_EXCLUDE_DEVICES] = []
            else:
                self.config[CONF_EXCLUDE_DEVICES] = [
                    device.strip() for device in exclude_devices_str.split(",") if device.strip()
                ]

        # Update extended entity discovery if provided
        if CONF_EXTENDED_ENTITY_DISCOVERY in user_input:
            self.config[CONF_EXTENDED_ENTITY_DISCOVERY] = user_input[CONF_EXTENDED_ENTITY_DISCOVERY]

        # Update debug mode if provided
        if CONF_DEBUG in user_input:
            self.config[CONF_DEBUG] = user_input[CONF_DEBUG]

    def __init__(self):
        """Initialize the config flow."""
        _LOGGER.debug("Initializing AlexaMediaFlowHandler")
        # self.hass is not available in __init__; any code that relies on self.hass should be moved to async methods
        self.login: Optional[AlexaLogin] = None
        self.securitycode: Optional[str] = None
        self.automatic_steps: int = 0
        self.config: dict = {}
        self.proxy: Optional[AlexaProxy] = None
        self.proxy_view: Optional["AlexaMediaAuthorizationProxyView"] = None
        self.config_entry: Optional[ConfigEntry] = None  # Initialize config_entry
        try:
            self.data_schema = self._create_schema(
                hass_url=DEFAULT_HASS_URL,
                public_url=DEFAULT_PUBLIC_URL
            )
            _LOGGER.debug("Initial data_schema created successfully")
        except Exception as e:
            _LOGGER.exception("Failed to create initial data_schema: %s", e)
            self.data_schema = vol.Schema({})
        _LOGGER.debug("AlexaMediaFlowHandler initialized successfully")

    def _get_hass_and_public_urls(self) -> tuple[str, str]:
        """Helper function to retrieve hass_url and public_url dynamically."""
        try:
            hass_url = get_url(self.hass, allow_external=False)
        except NoURLAvailableError:
            hass_url = DEFAULT_HASS_URL

        try:
            public_url = get_url(self.hass, allow_internal=False)
        except NoURLAvailableError:
            public_url = DEFAULT_PUBLIC_URL

        return hass_url, public_url

    def _create_schema(
        self, hass_url: str, public_url: str, include_proxy_warning: bool = False
    ) -> vol.Schema:
        """Create a centralized schema for user input validation."""
        _LOGGER.debug(
            "Creating schema with hass_url: %s, public_url: %s, include_proxy_warning: %s",
            hass_url,
            public_url,
            include_proxy_warning,
        )

        schema_dict = {
            vol.Required(CONF_URL, default=self.config.get(CONF_URL, "amazon.com")): TextSelector(
                TextSelectorConfig(type=TextSelectorType.TEXT)
            ),
            vol.Required(CONF_HASS_URL, default=hass_url): TextSelector(
                TextSelectorConfig(type=TextSelectorType.URL)
            ),
            vol.Optional(CONF_PUBLIC_URL, default=public_url): TextSelector(
                TextSelectorConfig(type=TextSelectorType.URL)
            ),
            vol.Required(CONF_EMAIL, default=self.config.get(CONF_EMAIL, "")): TextSelector(
                TextSelectorConfig(type=TextSelectorType.EMAIL)
            ),
        }

        # Determine if password is required or optional based on whether it is already stored
        if self.config.get(CONF_PASSWORD):
            schema_dict[vol.Optional(CONF_PASSWORD)] = TextSelector(
                TextSelectorConfig(type=TextSelectorType.PASSWORD)
            )
        else:
            schema_dict[vol.Required(CONF_PASSWORD)] = TextSelector(
                TextSelectorConfig(type=TextSelectorType.PASSWORD)
            )

        # Similarly for OTP Secret
        if self.config.get(CONF_OTPSECRET):
            schema_dict[vol.Optional(CONF_OTPSECRET)] = TextSelector(
                TextSelectorConfig(type=TextSelectorType.PASSWORD)
            )
        else:
            schema_dict[vol.Optional(CONF_OTPSECRET)] = TextSelector(
                TextSelectorConfig(type=TextSelectorType.PASSWORD)
            )

        # Add remaining fields with existing values
        schema_dict.update({
            vol.Optional(CONF_INCLUDE_DEVICES, default=", ".join(self.config.get(CONF_INCLUDE_DEVICES, []))): TextSelector(
                TextSelectorConfig(type=TextSelectorType.TEXT, multiline=False)
            ),
            vol.Optional(CONF_EXCLUDE_DEVICES, default=", ".join(self.config.get(CONF_EXCLUDE_DEVICES, []))): TextSelector(
                TextSelectorConfig(type=TextSelectorType.TEXT, multiline=False)
            ),
            vol.Optional(
                CONF_SCAN_INTERVAL,
                default=self.config.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
            ): NumberSelector(
                NumberSelectorConfig(min=1, max=3600)
            ),
            vol.Optional(
                CONF_QUEUE_DELAY,
                default=self.config.get(CONF_QUEUE_DELAY, DEFAULT_QUEUE_DELAY)
            ): NumberSelector(
                NumberSelectorConfig(min=0.1, max=10.0, step=0.1)
            ),
            vol.Optional(
                CONF_EXTENDED_ENTITY_DISCOVERY,
                default=self.config.get(CONF_EXTENDED_ENTITY_DISCOVERY, DEFAULT_EXTENDED_ENTITY_DISCOVERY)
            ): BooleanSelector(),
            vol.Optional(
                CONF_DEBUG,
                default=self.config.get(CONF_DEBUG, DEFAULT_DEBUG)
            ): BooleanSelector(),
        })

        if include_proxy_warning:
            _LOGGER.debug("Including proxy warning in schema")
            schema_dict[vol.Optional(CONF_PROXY_WARNING, default=False)] = BooleanSelector()

        schema = vol.Schema(schema_dict)

        _LOGGER.debug("Schema created successfully")
        return schema

    def serialize_config(self, config: dict[str, Any]) -> dict[str, Any]:
        """Serialize only the configuration data, excluding selectors."""
        serializable_config = {}
        for key, value in config.items():
            if key in [
                CONF_URL,
                CONF_EMAIL,
                CONF_PASSWORD,
                CONF_SECURITYCODE,
                CONF_OTPSECRET,
                CONF_HASS_URL,
                CONF_PUBLIC_URL,
                CONF_INCLUDE_DEVICES,
                CONF_EXCLUDE_DEVICES,
                CONF_SCAN_INTERVAL,
                CONF_QUEUE_DELAY,
                CONF_EXTENDED_ENTITY_DISCOVERY,
                CONF_DEBUG,
                CONF_PROXY_WARNING,
                CONF_TOTP_REGISTER,
                CONF_OAUTH,
            ]:
                serializable_config[key] = value
        return serializable_config

    async def _process_login(self, user_input: Optional[dict[str, Any]] = None) -> FlowResult:
        """Process login for both user and reauth flows."""
        # Process user input and update configuration
        self._save_user_input_to_config(user_input=user_input)

        account_email = self.config.get(CONF_EMAIL)
        if not account_email:
            _LOGGER.error("Email is required for login.")
            return self.async_abort(reason="email_required")

        # Initialize or retrieve existing AlexaLogin instance
        if self.login is None:
            existing_account = self.hass.data.get(DATA_ALEXAMEDIA, {}).get("accounts", {}).get(account_email)
            if existing_account:
                self.login = existing_account.get("login_obj")
                if self.login:
                    _LOGGER.debug("Retrieved existing login object for email: %s", account_email)
                else:
                    _LOGGER.debug("No existing login object found for email: %s", account_email)
            else:
                _LOGGER.debug("No existing account found for email: %s", account_email)

        try:
            # Create new AlexaLogin instance if necessary
            if not self.login or self.login.session.closed:
                _LOGGER.debug("Creating new AlexaLogin instance")
                uuid_dict = await calculate_uuid(self.hass, account_email, self.config.get(CONF_URL))
                uuid = uuid_dict["uuid"]
                # Create AlexaLogin directly in the main event loop
                self.login = AlexaLogin(
                    url=self.config.get(CONF_URL),
                    email=account_email,
                    password=self.config.get(CONF_PASSWORD, ""),
                    outputpath=self.hass.config.path,
                    debug=self.config.get(CONF_DEBUG),
                    otp_secret=self.config.get(CONF_OTPSECRET, ""),
                    oauth=self.config.get(CONF_OAUTH, {}),
                    uuid=uuid,
                    oauth_login=True,
                )
                _LOGGER.debug("New AlexaLogin instance created")
            else:
                _LOGGER.debug("Using existing AlexaLogin instance")
                # Update login credentials if they have changed
                updated = False
                if self.config.get(CONF_EMAIL) and self.login.email != self.config.get(CONF_EMAIL):
                    self.login.email = self.config.get(CONF_EMAIL)
                    updated = True
                    _LOGGER.debug("Updated login email to: %s", self.login.email)
                if self.config.get(CONF_PASSWORD) and self.login.password != self.config.get(CONF_PASSWORD):
                    self.login.password = self.config.get(CONF_PASSWORD)
                    updated = True
                    _LOGGER.debug("Updated login password")
                if self.config.get(CONF_OTPSECRET):
                    self.login.set_totp(self.config.get(CONF_OTPSECRET, ""))
                    updated = True
                    _LOGGER.debug("Set TOTP secret")
                if updated:
                    _LOGGER.debug("Login credentials updated")
        except AlexapyPyotpInvalidKey:
            _LOGGER.error("Invalid OTP key provided")
            return self.async_show_form(
                step_id="user",
                errors={"base": "2fa_key_invalid"},
                description_placeholders={"message": ""},
            )
        except Exception as e:
            _LOGGER.exception("Exception during login setup: %s", e)
            return self.async_abort(reason="login_setup_failed")

        # Validate Home Assistant URL
        hass_url = self.config.get(CONF_HASS_URL)
        if not hass_url:
            try:
                # Use helper function to retrieve URLs
                hass_url, public_url = self._get_hass_and_public_urls()
                _LOGGER.debug("Retrieved hass_url: %s", hass_url)
                self.config[CONF_HASS_URL] = hass_url
                self.config[CONF_PUBLIC_URL] = public_url
            except NoURLAvailableError:
                _LOGGER.debug("No Home Assistant URL found; prompting user")
                schema = self._create_schema(
                    hass_url=DEFAULT_HASS_URL,
                    public_url=DEFAULT_PUBLIC_URL,
                )
                return self.async_show_form(
                    step_id="user",
                    data_schema=schema,
                    description_placeholders={"message": "Please provide Home Assistant URL"},
                )

        # Check if hass_url is valid with retry logic
        hass_url_valid = False
        hass_url_error = ""
        retry_attempts = 3
        retry_delay = 2  # Seconds

        async with ClientSession() as session:
            for attempt in range(1, retry_attempts + 1):
                try:
                    _LOGGER.debug("Attempt %d: Checking hass_url: %s", attempt, hass_url)
                    async with session.get(hass_url, timeout=10) as resp:
                        if resp.status == 200:
                            hass_url_valid = True
                            _LOGGER.debug("hass_url is valid")
                            break
                        else:
                            hass_url_error = f"HTTP status {resp.status}"
                            _LOGGER.warning("Received non-200 response: %s", resp.status)
                except (ClientConnectionError, asyncio.TimeoutError) as err:
                    hass_url_error = str(err)
                    _LOGGER.warning("Attempt %d: Error connecting to hass_url: %s", attempt, err)
                    if attempt < retry_attempts:
                        await asyncio.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                    else:
                        _LOGGER.error("Max retry attempts reached for hass_url connection")
                except Exception as err:
                    hass_url_error = str(err)
                    _LOGGER.exception("Attempt %d: Exception while connecting to hass_url: %s", attempt, err)
                    break

        if not hass_url_valid:
            _LOGGER.error("Unable to connect to hass_url: %s, error: %s", hass_url, hass_url_error)
            proxy_warning_schema = self._create_schema(
                hass_url=DEFAULT_HASS_URL,
                public_url=DEFAULT_PUBLIC_URL,
                include_proxy_warning=True
            )
            _LOGGER.debug("Showing proxy warning form")
            return self.async_show_form(
                step_id="proxy_warning",
                data_schema=proxy_warning_schema,
                errors={"base": "hass_url_invalid"},
                description_placeholders={
                    "email": self.login.email,
                    "hass_url": hass_url,
                    "error": hass_url_error,
                },
            )

        # Handle reauthentication if needed
        if self.config.get("reauth"):
            _LOGGER.debug("Handling reauth flow")
            seconds_since_login = 60
            if self.login and "login_timestamp" in self.login.stats:
                seconds_since_login = (datetime.datetime.now() - self.login.stats["login_timestamp"]).total_seconds()
            if seconds_since_login < 60:
                _LOGGER.debug("Recent login detected; manual reauth required")
                reauth_schema = self._create_schema(
                    hass_url=hass_url,
                    public_url=self.config.get(CONF_PUBLIC_URL, DEFAULT_PUBLIC_URL),
                )
                return self.async_show_form(
                    step_id="user",
                    data_schema=reauth_schema,
                    description_placeholders={"message": "Please re-enter your credentials"},
                )

        # Handle OTP Secret
        otp_secret = self.config.get(CONF_OTPSECRET)
        if otp_secret:
            otp_token = self.login.get_totp_token()
            if otp_token:
                _LOGGER.debug("Generated OTP token")
                return self.async_show_form(
                    step_id="totp_register",
                    data_schema=vol.Schema(
                        {
                            vol.Optional(CONF_TOTP_REGISTER, default=False): BooleanSelector(
                                BooleanSelectorConfig()
                            ),
                        }
                    ),
                    errors={},
                    description_placeholders={
                        "email": self.login.email,
                        "url": self.login.url,
                        "message": otp_token,
                    },
                )
            else:
                _LOGGER.warning("Failed to generate OTP token")
                return self.async_show_form(
                    step_id="user",
                    errors={"base": "otp_generation_failed"},
                    description_placeholders={"message": "Failed to generate OTP token"},
                )

        # Handle login success
        if self.login.status and self.login.status.get("login_successful"):
            email = self.login.email
            unique_id = f"{email} - {self.login.url}"
            _LOGGER.debug("Setting unique ID: %s", unique_id)
            serialized_data = self.serialize_config(self.config)
            try:
                await self.async_set_unique_id(unique_id, raise_on_progress=False)
                self._abort_if_unique_id_configured()
            except AbortFlow as e:
                if e.reason == 'already_configured':
                    existing_entry = next(
                        (entry for entry in self.hass.config_entries.async_entries(DOMAIN)
                         if entry.unique_id == unique_id),
                        None
                    )
                    if existing_entry:
                        _LOGGER.debug("Updating existing config entry")
                        self.hass.config_entries.async_update_entry(existing_entry, data=serialized_data)
                        _LOGGER.debug("Reauth successful for %s", hide_email(email))
                        self.hass.bus.async_fire(
                            "alexa_media_relogin_success",
                            event_data={"email": hide_email(email), "url": self.login.url},
                        )
                        async_dismiss_persistent_notification(
                            self.hass,
                            notification_id=f"alexa_media_{slugify(email)}{slugify(self.login.url[7:])}",
                        )
                        # Update internal data structures
                        self.hass.data.setdefault(DATA_ALEXAMEDIA, {}).setdefault("accounts", {}).setdefault(email, {})["login_obj"] = self.login
                        self.hass.data[DATA_ALEXAMEDIA]["config_flows"][unique_id] = None
                        return self.async_abort(reason="reauth_successful")
                    else:
                        _LOGGER.error("Unique ID already exists but no existing entry found.")
                        return self.async_abort(reason="unique_id_conflict")
                else:
                    # Re-raise other AbortFlow exceptions
                    raise

            _LOGGER.debug("Creating new config entry")
            return self.async_create_entry(
                title=f"{self.login.email} - {self.login.url}", data=serialized_data
            )

        # Handle security code requirement
        if self.login.status and self.login.status.get("securitycode_required"):
            _LOGGER.debug("Security code required")
            generated_securitycode = self.login.get_totp_token()
            if (self.securitycode or generated_securitycode) and self.automatic_steps < 2:
                self.automatic_steps += 1
                await asyncio.sleep(5)
                security_code = generated_securitycode or self.securitycode
                if security_code:
                    _LOGGER.debug("Automatically submitting security code")
                    return await self.async_step_user_legacy(
                        user_input={CONF_SECURITYCODE: security_code}
                    )
            else:
                _LOGGER.debug("Security code submission conditions not met")

        # Handle login failure
        if self.login.status and self.login.status.get("login_failed"):
            _LOGGER.error("Login failed: %s", self.login.status.get("login_failed"))
            await self.login.close()
            await self._unregister_views()
            async_dismiss_persistent_notification(
                self.hass,
                notification_id=f"alexa_media_{slugify(self.login.email)}{slugify(self.login.url[7:])}",
            )
            return self.async_abort(reason="login_failed")

        # Handle other error messages
        error_message = self.login.status.get("error_message", "")
        if error_message:
            _LOGGER.error("Login error: %s", error_message)
            if "Enter a valid email" in error_message and self.automatic_steps < 2:
                self.automatic_steps += 1
                await asyncio.sleep(5)
                return await self.async_step_user_legacy(user_input=self.config)
            else:
                self.automatic_steps = 0
                await self._unregister_views()
                return self.async_show_form(
                    step_id="user",
                    data_schema=self._create_schema(
                        hass_url=hass_url,
                        public_url=self.config.get(CONF_PUBLIC_URL, DEFAULT_PUBLIC_URL),
                    ),
                    errors={"base": "login_error"},
                    description_placeholders={"message": error_message},
                )

        # If we reach here, show the user form again with an unknown error
        self.automatic_steps = 0
        return self.async_show_form(
            step_id="user",
            data_schema=self._create_schema(
                hass_url=hass_url,
                public_url=self.config.get(CONF_PUBLIC_URL, DEFAULT_PUBLIC_URL),
            ),
            errors={"base": "unknown_error"},
            description_placeholders={"message": "An unknown error occurred"},
        )

    async def async_step_import(self, import_config: dict[str, Any]) -> FlowResult:
        """Import a config entry from configuration.yaml."""
        _LOGGER.debug("Importing config from YAML: %s", import_config)
        return await self.async_step_user_legacy(import_config)

    async def async_step_user(self, user_input: Optional[dict[str, Any]] = None) -> FlowResult:
        """
        Handle the user step of the config flow.

        Home Assistant handles login and authentication within _process_login.
        If external authentication is required, it will be handled using async_external_step.
        """
        _LOGGER.debug("Entered async_step_user")

        # Initialize alexapy if necessary
        if not self.hass.data.get(DATA_ALEXAMEDIA):
            _LOGGER.info(STARTUP)
            _LOGGER.info("Loaded alexapy==%s", alexapy_version)

        if user_input is None:
            _LOGGER.debug("No user_input provided. Showing user form.")

            # Use the helper function to get dynamic URLs
            try:
                hass_url, public_url = self._get_hass_and_public_urls()
                _LOGGER.debug("Retrieved hass_url: %s and public_url: %s", hass_url, public_url)
            except NoURLAvailableError:
                _LOGGER.error("No Home Assistant URL available.")
                return self.async_abort(reason="no_url_available")

            # Create the schema for the user form
            schema = self._create_schema(
                hass_url=self.config.get(CONF_HASS_URL, hass_url),
                public_url=self.config.get(CONF_PUBLIC_URL, public_url),
            )
            _LOGGER.debug("Created user schema successfully")

            # Show the form to the user
            return self.async_show_form(
                step_id="user",
                data_schema=schema,
                description_placeholders={"message": ""},
            )

        _LOGGER.debug("User input provided. Processing input.")

        # Save user input to the configuration
        try:
            self._save_user_input_to_config(user_input=user_input)
            _LOGGER.debug("User input saved to config")
        except ValueError as e:
            _LOGGER.error("Invalid user input: %s", e)
            return self.async_show_form(
                step_id="user",
                data_schema=self._create_schema(
                    hass_url=self.config.get(CONF_HASS_URL),
                    public_url=self.config.get(CONF_PUBLIC_URL),
                ),
                errors={"base": "invalid_input"},
                description_placeholders={"message": str(e)},
            )

        # Process login using the common login method
        return await self._process_login(user_input)

    async def async_step_user_legacy(self, user_input: Optional[dict[str, Any]] = None) -> FlowResult:
        """Handle legacy input for the config flow."""
        _LOGGER.debug("Entered async_step_user_legacy with user_input: %s", user_input)
        self._save_user_input_to_config(user_input=user_input)

        # Show form if no user_input is provided
        if not user_input:
            _LOGGER.debug("No user_input provided in legacy step. Showing user form.")
            self.automatic_steps = 0
            
            # Use the helper function to get dynamic URLs
            hass_url, public_url = self._get_hass_and_public_urls()

            try:
                schema = self._create_schema(
                    hass_url=self.config.get(CONF_HASS_URL, hass_url),
                    public_url=self.config.get(CONF_PUBLIC_URL, public_url),
                )
                _LOGGER.debug("Created legacy user schema successfully")
            except Exception as e:
                _LOGGER.exception("Exception while creating legacy user schema: %s", e)
                return self.async_abort(reason="schema_creation_failed")

            return self.async_show_form(
                step_id="user",
                data_schema=schema,
                description_placeholders={"message": ""},
            )

        # Check if the account already exists
        if (
            not self.config.get("reauth")
            and f"{self.config[CONF_EMAIL]} - {self.config[CONF_URL]}"
            in configured_instances(self.hass)
            and not self.hass.data[DATA_ALEXAMEDIA]["config_flows"].get(
                f"{self.config[CONF_EMAIL]} - {self.config[CONF_URL]}"
            )
        ):
            _LOGGER.debug("Existing account found during legacy step")
            self.automatic_steps = 0
            return self.async_show_form(
                step_id="user",
                data_schema=self.data_schema,  # Use the already initialized data_schema
                errors={CONF_EMAIL: "identifier_exists"},
                description_placeholders={"message": ""},
            )

        # Delegate login processing to the centralized method
        return await self._process_login(user_input)

    async def async_step_totp_register(self, user_input: Optional[dict[str, Any]] = None) -> FlowResult:
        """Handle the input processing of the config flow."""
        self._save_user_input_to_config(user_input=user_input)
        if user_input and not user_input.get(CONF_TOTP_REGISTER, False):
            _LOGGER.debug("Not registered, regenerating")
            otp: str = self.login.get_totp_token()
            if otp:
                _LOGGER.debug("Generating OTP from %s", otp)
                # Embed the BooleanSelector directly into the schema
                data_schema = vol.Schema({
                    vol.Optional(CONF_TOTP_REGISTER, default=False): BooleanSelector(
                        BooleanSelectorConfig()
                    ),
                })

                return self.async_show_form(
                    step_id="totp_register",
                    data_schema=data_schema,
                    description_placeholders={
                        "email": self.login.email,
                        "url": self.login.url,
                        "message": otp,
                    },
                )
        return await self.async_step_start_proxy(user_input)

    async def async_step_reauth(self, user_input: Optional[dict[str, Any]] = None) -> FlowResult:
        """Handle reauth processing for the config flow."""
        _LOGGER.debug("Entered async_step_reauth with user_input: %s", user_input)
        self._save_user_input_to_config(user_input)
        self.config["reauth"] = True

        try:
            return await self._process_login(user_input=self.config)
        except Exception as e:
            _LOGGER.exception("Exception during reauth: %s", e)
            await self._unregister_views()
            return self.async_abort(reason="reauth_failed")

    async def async_step_reconfigure(self, user_input: Optional[dict[str, Any]] = None) -> FlowResult:
        """Handle reconfiguration of an existing entry."""
        _LOGGER.debug("Entered async_step_reconfigure")

        # Ensure self.config_entry is initialized
        if not self.config_entry:
            _LOGGER.debug("config_entry not set, retrieving from context")
            self.config_entry = self.hass.config_entries.async_get_entry(self.context.get("entry_id"))
            if not self.config_entry:
                _LOGGER.error("No config_entry found during reconfiguration")
                return self.async_abort(reason="no_config_entry")

        # Load existing configuration data
        existing_data = self.config_entry.data
        self.config = self.serialize_config(existing_data)
        _LOGGER.debug("Loaded existing configuration data for reconfiguration")

        # Ensure the unique ID is correctly set
        unique_id = f"{self.config.get(CONF_EMAIL)} - {self.config.get(CONF_URL)}"
        _LOGGER.debug("Setting unique_id to: %s", unique_id)
        try:
            await self.async_set_unique_id(unique_id)
        except ValueError:
            _LOGGER.debug("Unique ID is already set")
        except HomeAssistantError as e:
            _LOGGER.error("Error setting unique_id: %s", e)
            await self._unregister_views()
            return self.async_abort(reason="unique_id_error")

        # Handle user input if provided
        if user_input is not None:
            _LOGGER.debug("Processing user input for reconfiguration")
            try:
                # Update config with user input
                updated_config = self.config.copy()
                for key in [
                    CONF_EMAIL, CONF_URL, CONF_HASS_URL, CONF_PUBLIC_URL,
                    CONF_SCAN_INTERVAL, CONF_QUEUE_DELAY, CONF_EXTENDED_ENTITY_DISCOVERY,
                    CONF_DEBUG, CONF_INCLUDE_DEVICES, CONF_EXCLUDE_DEVICES
                ]:
                    # Update the value even if it's an empty string
                    if key in user_input:
                        updated_config[key] = user_input[key]
                    else:
                        # Retain existing value if key not in user_input
                        updated_config[key] = existing_data.get(key)

                # Handle password and OTP secret separately
                if user_input.get(CONF_PASSWORD) is not None:
                    updated_config[CONF_PASSWORD] = user_input[CONF_PASSWORD]
                else:
                    # Retain existing password if not provided
                    updated_config[CONF_PASSWORD] = existing_data.get(CONF_PASSWORD)

                if user_input.get(CONF_OTPSECRET) is not None:
                    updated_config[CONF_OTPSECRET] = user_input[CONF_OTPSECRET]
                else:
                    # Retain existing OTP secret if not provided
                    updated_config[CONF_OTPSECRET] = existing_data.get(CONF_OTPSECRET)

                # Serialize updated config
                self.config = updated_config

                # Update the existing config entry with new data
                self.hass.config_entries.async_update_entry(
                    self.config_entry,
                    data=self.serialize_config(self.config),
                    options=self.config_entry.options,
                )
                _LOGGER.debug("Reconfiguration successful")

                # Reload the configuration to apply changes
                await self.hass.config_entries.async_reload(self.config_entry.entry_id)
                return self.async_abort(reason="reconfigure_successful")
            except Exception as e:
                _LOGGER.exception("Exception during reconfiguration: %s", e)
                return self.async_show_form(
                    step_id="reconfigure",
                    data_schema=self._create_schema(
                        hass_url=self.config.get(CONF_HASS_URL, DEFAULT_HASS_URL),
                        public_url=self.config.get(CONF_PUBLIC_URL, DEFAULT_PUBLIC_URL),
                        include_proxy_warning=False,
                    ),
                    errors={"base": "reconfigure_failed"},
                    description_placeholders={"message": str(e)},
                )

        # Create the schema using existing data as defaults
        reconfig_schema = self._create_schema(
            hass_url=self.config.get(CONF_HASS_URL, DEFAULT_HASS_URL),
            public_url=self.config.get(CONF_PUBLIC_URL, DEFAULT_PUBLIC_URL),
            include_proxy_warning=False,
        )
        _LOGGER.debug("Reconfiguration schema created successfully")

        # Show the reconfiguration form to the user
        _LOGGER.debug("Showing reconfigure form to the user")
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=reconfig_schema,
            description_placeholders={"message": ""},
        )

    async def _test_login(self, serialized_data: dict) -> FlowResult:
        """Test the login status and create or update the config entry."""
        login = self.login
        email = login.email
        _LOGGER.debug("Testing login status: %s", self.login.status)

        if self.login.status and self.login.status.get("login_successful"):
            unique_id = f"{email} - {login.url}"
            _LOGGER.debug("Setting unique ID: %s", unique_id)
            try:
                await self.async_set_unique_id(unique_id, raise_on_progress=False)
                self._abort_if_unique_id_configured()
            except AbortFlow as e:
                if e.reason == 'already_configured':
                    existing_entry = next(
                        (entry for entry in self.hass.config_entries.async_entries(DOMAIN) if entry.unique_id == unique_id),
                        None
                    )
                    if existing_entry:
                        _LOGGER.debug("Updating existing config entry")
                        self.hass.config_entries.async_update_entry(
                            existing_entry, data=serialized_data
                        )
                        _LOGGER.debug("Reauth successful for %s", hide_email(email))
                        self.hass.bus.async_fire(
                            "alexa_media_relogin_success",
                            event_data={"email": hide_email(email), "url": self.login.url},
                        )
                        async_dismiss_persistent_notification(
                            self.hass,
                            notification_id=f"alexa_media_{slugify(email)}{slugify(login.url[7:])}",
                        )
                        # Update internal data structures
                        self.hass.data.setdefault(DATA_ALEXAMEDIA, {}).setdefault("accounts", {}).setdefault(email, {})["login_obj"] = self.login
                        self.hass.data[DATA_ALEXAMEDIA]["config_flows"][unique_id] = None
                        return self.async_abort(reason="reauth_successful")
                    else:
                        _LOGGER.error("Unique ID already exists but no existing entry found.")
                        await self._unregister_views()
                        return self.async_abort(reason="unique_id_conflict")
                else:
                    # Re-raise other AbortFlow exceptions
                    raise

            _LOGGER.debug("No existing entry found. Creating new config entry.")
            entry = self.async_create_entry(
                title=f"{login.email} - {login.url}", data=serialized_data
            )
            # Do not unregister views on successful entry creation
            return entry

        # Handle security code requirement
        if self.login.status and self.login.status.get("securitycode_required"):
            _LOGGER.debug("Security code required")
            generated_securitycode = self.login.get_totp_token()
            if (self.securitycode or generated_securitycode) and self.automatic_steps < 2:
                self.automatic_steps += 1
                await asyncio.sleep(5)
                security_code = generated_securitycode or self.securitycode
                if security_code:
                    _LOGGER.debug("Automatically submitting security code")
                    return await self.async_step_user_legacy(
                        user_input={CONF_SECURITYCODE: security_code}
                    )
            else:
                _LOGGER.debug("Security code submission conditions not met")

        # Handle login failure
        if self.login.status and self.login.status.get("login_failed"):
            _LOGGER.error("Login failed: %s", self.login.status.get("login_failed"))
            await self.login.close()
            await self._unregister_views()
            async_dismiss_persistent_notification(
                self.hass,
                notification_id=f"alexa_media_{slugify(email)}{slugify(login.url[7:])}",
            )
            return self.async_abort(reason="login_failed")

        # Handle other error messages
        error_message = self.login.status.get("error_message", "")
        if error_message:
            _LOGGER.error("Login error: %s", error_message)
            if "Enter a valid email" in error_message and self.automatic_steps < 2:
                self.automatic_steps += 1
                await asyncio.sleep(5)
                return await self.async_step_user_legacy(user_input=self.config)
            else:
                self.automatic_steps = 0
                await self._unregister_views()
                return self.async_show_form(
                    step_id="user",
                    data_schema=self._create_schema(
                        hass_url=self.config.get(CONF_HASS_URL, DEFAULT_HASS_URL),
                        public_url=self.config.get(CONF_PUBLIC_URL, DEFAULT_PUBLIC_URL),
                    ),
                    errors={"base": "login_error"},
                    description_placeholders={"message": error_message},
                )

        # If we reach here, show the user form again with an unknown error
        self.automatic_steps = 0
        await self._unregister_views()
        return self.async_show_form(
            step_id="user",
            data_schema=self._create_schema(
                hass_url=self.config.get(CONF_HASS_URL, DEFAULT_HASS_URL),
                public_url=self.config.get(CONF_PUBLIC_URL, DEFAULT_PUBLIC_URL),
            ),
            errors={"base": "unknown_error"},  # Use a generic error code
            description_placeholders={"message": "An unknown error occurred"},
        )

    async def async_step_start_proxy(self, user_input=None):
        """Start proxy for login."""
        _LOGGER.debug(
            "Starting proxy for %s - %s",
            hide_email(self.login.email),
            self.login.url,
        )

        # Store the login object in the flow context
        self.context['login_obj'] = self.login

        if not self.proxy:
            try:
                self.proxy = AlexaProxy(
                    self.login,
                    str(URL(self.config.get(CONF_HASS_URL)).with_path(AUTH_PROXY_PATH)),
                )
            except ValueError as ex:
                return self.async_show_form(
                    step_id="user",
                    errors={"base": "invalid_url"},
                    description_placeholders={"message": str(ex)},
                )

        if not self.proxy_view:
            self.proxy_view = AlexaMediaAuthorizationProxyView(self.proxy.all_handler)
        else:
            _LOGGER.debug("Found existing proxy_view")
            self.proxy_view.handler = self.proxy.all_handler

        self.hass.http.register_view(AlexaMediaAuthorizationCallbackView())
        self.hass.http.register_view(self.proxy_view)

        callback_url = (
            URL(self.config.get(CONF_HASS_URL))
            .with_path(AUTH_CALLBACK_PATH)
            .with_query({"flow_id": self.flow_id})
        )

        proxy_url = self.proxy.access_url().with_query(
            {"config_flow_id": self.flow_id, "callback_url": str(callback_url)}
        )

        self.login._session.cookie_jar.clear()  # pylint: disable=protected-access
        self.login.proxy_url = proxy_url

        return self.async_external_step(step_id="check_proxy", url=str(proxy_url))

    async def async_step_check_proxy(self, user_input: Optional[dict[str, Any]] = None) -> FlowResult:
        """
        Handle the callback from the external proxy after authentication.
        
        After external authentication, Home Assistant's async_external_step_done
        is called to proceed with the next step.
        """
        _LOGGER.debug("Entered async_step_check_proxy with user_input: %s", user_input)
        # Home Assistant Core method async_external_step_done signals the
        # completion of an external authentication step.
        if self.proxy:
            return self.async_external_step_done(next_step_id="finish_proxy")
        else:
            _LOGGER.error("Proxy not initialized")
            await self._unregister_views()
            return self.async_abort(reason="proxy_initialization_failed")

    async def async_step_finish_proxy(self, user_input: Optional[dict[str, Any]] = None) -> FlowResult:
        """Finish authentication process."""
        _LOGGER.debug("Entered async_step_finish_proxy with user_input: %s", user_input)
        try:
            if self.login is not None and await self.login.test_loggedin():
                _LOGGER.debug("Login test successful. Finalizing login.")
                await self.login.finalize_login()
                self.config[CONF_EMAIL] = self.login.email
                self.config[CONF_PASSWORD] = self.login.password
                serialized_data = self.serialize_config(self.config)
                result = await self._test_login(serialized_data)
                # Do NOT unregister views on successful login
                return result
            else:
                _LOGGER.warning("Login test failed. Aborting flow.")
                await self._unregister_views()
                return self.async_abort(reason="login_test_failed")
        except Exception as e:
            _LOGGER.exception("Exception in async_step_finish_proxy: %s", e)
            await self._unregister_views()
            return self.async_abort(reason="login_exception")

    async def _unregister_views(self) -> None:
        """Unregister views and clean up resources."""
        _LOGGER.debug("Unregistering views and cleaning up resources.")
        # Clear the proxy view reference
        if self.proxy_view:
            self.proxy_view = None
            _LOGGER.debug("Proxy view reference cleared.")

        # Clear the callback view reference
        self.callback_view = None
        _LOGGER.debug("Callback view reference cleared.")

        # No need to unregister views explicitly

        # Remove the call to self.proxy.close()
        if self.proxy:
            _LOGGER.debug("Proxy does not have a close method. Skipping.")
            self.proxy = None

        # Close the AlexaLogin session
        if self.login and not self.login.session.closed:
            await self.login.close()
            _LOGGER.debug("AlexaLogin session closed.")
            self.login = None

    def _handle_error(self, error_type: str, message: Any) -> FlowResult:
        """Handle errors and return the form with a detailed error message."""
        masked_message = obfuscate(str(message)) if isinstance(message, str) else "An error occurred."
        _LOGGER.error(f"Error occurred in {error_type}: {masked_message}")

        user_message = error_type

        hass_url = self.config.get(CONF_HASS_URL, DEFAULT_HASS_URL)
        public_url = self.config.get(CONF_PUBLIC_URL, DEFAULT_PUBLIC_URL)

        schema = self._create_schema(
            hass_url=hass_url,
            public_url=public_url,
        )

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors={"base": user_message},
            description_placeholders={"message": masked_message},
        )



class OptionsFlowHandler(config_entries.OptionsFlow):
    """Handle a option flow for Alexa Media."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self.config = {}
        self.config_entry = config_entry

    async def async_step_init(
        self, user_input: Optional[dict[str, Any]] = None
    ) -> FlowResult:
        """Manage the options."""

        options_schema = vol.Schema({
            vol.Optional(CONF_PUBLIC_URL, default=self.config_entry.data.get(CONF_PUBLIC_URL, DEFAULT_PUBLIC_URL)): TextSelector(
                TextSelectorConfig(type=TextSelectorType.URL)
            ),
            vol.Optional(CONF_INCLUDE_DEVICES, default=", ".join(self.config_entry.options.get(CONF_INCLUDE_DEVICES, []))): TextSelector(
                TextSelectorConfig(type=TextSelectorType.TEXT, multiline=False)
            ),
            vol.Optional(CONF_EXCLUDE_DEVICES, default=", ".join(self.config_entry.options.get(CONF_EXCLUDE_DEVICES, []))): TextSelector(
                TextSelectorConfig(type=TextSelectorType.TEXT, multiline=False)
            ),
            vol.Optional(CONF_SCAN_INTERVAL, default=self.config_entry.data.get(CONF_SCAN_INTERVAL, 120)): NumberSelector(
                NumberSelectorConfig(min=1, max=3600)
            ),
            vol.Optional(CONF_QUEUE_DELAY, default=self.config_entry.data.get(CONF_QUEUE_DELAY, DEFAULT_QUEUE_DELAY)): NumberSelector(
                NumberSelectorConfig(min=0.1, max=10.0, step=0.1)
            ),
            vol.Optional(CONF_EXTENDED_ENTITY_DISCOVERY, default=self.config_entry.data.get(CONF_EXTENDED_ENTITY_DISCOVERY, DEFAULT_EXTENDED_ENTITY_DISCOVERY)): BooleanSelector(
                BooleanSelectorConfig()
            ),
            vol.Optional(CONF_DEBUG, default=self.config_entry.data.get(CONF_DEBUG, DEFAULT_DEBUG)): BooleanSelector(
                BooleanSelectorConfig()
            ),
        })

        if user_input is not None:
            """Preserve these parameters"""
            preserved_fields = [
                CONF_URL,
                CONF_EMAIL,
                CONF_PASSWORD,
                CONF_SECURITYCODE,
                CONF_OTPSECRET,
                CONF_OAUTH,
            ]
            for field in preserved_fields:
                if field in self.config_entry.data:
                    user_input[field] = self.config_entry.data[field]

            self.hass.config_entries.async_update_entry(
                self.config_entry, 
                data=self.config_entry.data,
                options=user_input
            )
            return self.async_create_entry(title="", data={})

        return self.async_show_form(
            step_id="init",
            data_schema=options_schema,
            description_placeholders={"message": ""},
        )



class AlexaMediaAuthorizationCallbackView(HomeAssistantView):
    """Handle callback from external auth."""

    url = AUTH_CALLBACK_PATH
    name = AUTH_CALLBACK_NAME
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Receive authorization confirmation."""
        hass = request.app["hass"]
        try:
            await hass.config_entries.flow.async_configure(
                flow_id=request.query["flow_id"], user_input=None
            )
        except (KeyError, UnknownFlow) as ex:
            _LOGGER.debug("Callback flow_id is invalid.")
            raise HTTPBadRequest() from ex
        return web.Response(
            headers={"content-type": "text/html"},
            text="<script>window.close()</script>Success! This window can be closed",
        )



class AlexaMediaAuthorizationProxyView(HomeAssistantView):
    """Handle proxy connections."""

    url = AUTH_PROXY_PATH
    extra_urls = [f"{AUTH_PROXY_PATH}/{{tail:.*}}"]
    name = AUTH_PROXY_NAME
    requires_auth = False
    known_ips: dict[str, datetime.datetime] = {}
    auth_seconds: int = 300

    def __init__(self, handler: web.RequestHandler) -> None:
        """Initialize routes for view."""
        self.handler = handler
        for method in ("get", "post", "delete", "put", "patch", "head", "options"):
            setattr(self, method, self.check_auth())

    def check_auth(self):
        """Wrap authentication into the handler."""

        async def wrapped(request, **kwargs):
            """Authenticate and handle the request."""
            hass = request.app["hass"]
            success = False
            if (
                request.remote not in self.known_ips
                or (
                    datetime.datetime.now()
                    - self.known_ips.get(request.remote, datetime.datetime.now())
                ).seconds
                > self.auth_seconds
            ):
                try:
                    flow_id = request.query["config_flow_id"]
                except KeyError as ex:
                    raise Unauthorized() from ex
                for flow in hass.config_entries.flow.async_progress():
                    if flow["flow_id"] == flow_id:
                        _LOGGER.debug(
                            "Found flow_id; adding %s to known_ips for %s seconds",
                            request.remote,
                            self.auth_seconds,
                        )
                        success = True
                        break
                if not success:
                    raise Unauthorized()
                self.known_ips[request.remote] = datetime.datetime.now()
            try:
                return await self.handler(request, **kwargs)
            except ClientConnectionError as ex:
                _LOGGER.warning("Detected Connection error: %s", ex)
                return web.Response(
                    headers={"content-type": "text/html"},
                    text="Connection Error! Please try refreshing. "
                    + "If this persists, please report this error to "
                    + f"<a href={ISSUE_URL}>here</a>:<br /><pre>{ex}</pre>",
                )

        return wrapped

    @classmethod
    def reset(cls) -> None:
        """Reset the view."""
        cls.known_ips = {}
