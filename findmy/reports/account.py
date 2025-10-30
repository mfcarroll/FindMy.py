"""Module containing most of the code necessary to interact with an Apple account."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import plistlib
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Literal,
    TypedDict,
    TypeVar,
    Optional,
    Sequence,
    cast,
    overload,
)

import bs4
import srp._pysrp as srp
from typing_extensions import Concatenate, ParamSpec, override

from findmy import util
from findmy.errors import (
    InvalidCredentialsError,
    InvalidStateError,
    UnauthorizedError,
    UnhandledProtocolError,
    PushError,
)
from findmy.keychain.cloudkit_manager import CloudKitManager
from findmy.util.http import HttpSession
from findmy.keychain import identity

from .anisette import AnisetteMapping, get_provider_from_mapping
from .reports import LocationReport, LocationReportsFetcher
from .state import LoginState
from .twofactor import (
    AsyncSecondFactorMethod,
    AsyncSmsSecondFactor,
    AsyncTrustedDeviceSecondFactor,
    BaseSecondFactorMethod,
    SyncSecondFactorMethod,
    SyncSmsSecondFactor,
    SyncTrustedDeviceSecondFactor,
)

from findmy.keychain import cloudkit_pb2 as ckproto
from findmy.keychain.identity import KeychainUserIdentity

from google.protobuf.message import Message

# --- Add this logging configuration ---
logging.basicConfig(
    level=logging.DEBUG,  # Capture detailed logs
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s", # Added logger name
    handlers=[
        logging.FileHandler("account_debug.log", mode='w'), # Log to file, overwrite each run
        logging.StreamHandler() # Log to console
    ]
)
# Make sure logger name matches the one used later (default is root)
logger = logging.getLogger(__name__) # Use the module's logger instance
# --- End of new code ---

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from findmy.accessory import RollingKeyPairSource
    from findmy.keys import HasHashedPublicKey
    from findmy.util.types import MaybeCoro

    from .anisette import BaseAnisetteProvider

logger = logging.getLogger(__name__)

srp.rfc5054_enable()
srp.no_username_in_x()


class _AccountInfo(TypedDict):
    account_name: str
    first_name: str
    last_name: str
    trusted_device_2fa: bool


class _AccountStateMappingIds(TypedDict):
    uid: str
    devid: str


class _AccountStateMappingAccount(TypedDict):
    username: str | None
    password: str | None
    info: _AccountInfo | None


class _AccountStateMappingLoginState(TypedDict):
    state: int
    data: dict  # TODO: make typed  # noqa: TD002, TD003


class AccountStateMapping(TypedDict):
    """JSON mapping representing state of an Apple account instance."""

    type: Literal["account"]

    ids: _AccountStateMappingIds
    account: _AccountStateMappingAccount
    login: _AccountStateMappingLoginState
    anisette: AnisetteMapping


_P = ParamSpec("_P")
_R = TypeVar("_R")
_A = TypeVar("_A", bound="BaseAppleAccount")
_F = Callable[Concatenate[_A, _P], _R]


def _require_login_state(*states: LoginState) -> Callable[[_F], _F]:
    """Enforce a login state as precondition for a method."""

    def decorator(func: _F) -> _F:
        @wraps(func)
        def wrapper(acc: _A, *args: _P.args, **kwargs: _P.kwargs) -> _R:  # pyright: ignore [reportInvalidTypeVarUse]
            if not isinstance(acc, BaseAppleAccount):
                msg = "This decorator can only be used on instances of BaseAppleAccount."
                raise TypeError(msg)

            if acc.login_state not in states:
                msg = (
                    f"Invalid login state! Currently: {acc.login_state}"
                    f" but should be one of: {states}"
                )
                raise InvalidStateError(msg)

            return func(acc, *args, **kwargs)

        return wrapper

    return decorator


def _extract_phone_numbers(html: str) -> list[dict]:
    soup = bs4.BeautifulSoup(html, features="html.parser")
    data_elem = soup.find("script", {"class": "boot_args"})
    if not data_elem:
        msg = "Could not find HTML element containing phone numbers"
        raise RuntimeError(msg)

    data = json.loads(data_elem.text)
    return data.get("direct", {}).get("phoneNumberVerification", {}).get("trustedPhoneNumbers", [])


class BaseAppleAccount(util.abc.Closable, util.abc.Serializable[AccountStateMapping], ABC):
    """Base class for an Apple account."""

    @property
    @abstractmethod
    def login_state(self) -> LoginState:
        """The current login state of the account."""
        raise NotImplementedError

    @property
    @abstractmethod
    def account_name(self) -> str | None:
        """
        The name of the account as reported by Apple.

        This is usually an e-mail address.
        May be None in some cases, such as when not logged in.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def first_name(self) -> str | None:
        """
        First name of the account holder as reported by Apple.

        May be None in some cases, such as when not logged in.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def last_name(self) -> str | None:
        """
        Last name of the account holder as reported by Apple.

        May be None in some cases, such as when not logged in.
        """
        raise NotImplementedError

    @abstractmethod
    def login(self, username: str, password: str) -> MaybeCoro[LoginState]:
        """Log in to an Apple account using a username and password."""
        raise NotImplementedError

    @abstractmethod
    def get_2fa_methods(self) -> MaybeCoro[Sequence[BaseSecondFactorMethod]]:
        """
        Get a list of 2FA methods that can be used as a secondary challenge.

        Currently, only SMS-based 2FA methods are supported.
        """
        raise NotImplementedError

    @abstractmethod
    def sms_2fa_request(self, phone_number_id: int) -> MaybeCoro[None]:
        """
        Request a 2FA code to be sent to a specific phone number ID.

        Consider using :meth:`BaseSecondFactorMethod.request` instead.
        """
        raise NotImplementedError

    @abstractmethod
    def sms_2fa_submit(self, phone_number_id: int, code: str) -> MaybeCoro[LoginState]:
        """
        Submit a 2FA code that was sent to a specific phone number ID.

        Consider using :meth:`BaseSecondFactorMethod.submit` instead.
        """
        raise NotImplementedError

    @abstractmethod
    def td_2fa_request(self) -> MaybeCoro[None]:
        """
        Request a 2FA code to be sent to a trusted device.

        Consider using :meth:`BaseSecondFactorMethod.request` instead.
        """
        raise NotImplementedError

    @abstractmethod
    def td_2fa_submit(self, code: str) -> MaybeCoro[LoginState]:
        """
        Submit a 2FA code that was sent to a trusted device.

        Consider using :meth:`BaseSecondFactorMethod.submit` instead.
        """
        raise NotImplementedError

    @overload
    @abstractmethod
    def fetch_location_history(
        self,
        keys: HasHashedPublicKey,
    ) -> MaybeCoro[list[LocationReport]]: ...

    @overload
    @abstractmethod
    def fetch_location_history(
        self,
        keys: RollingKeyPairSource,
    ) -> MaybeCoro[list[LocationReport]]: ...

    @overload
    @abstractmethod
    def fetch_location_history(
        self,
        keys: Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> MaybeCoro[dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]]: ...

    @abstractmethod
    def fetch_location_history(
        self,
        keys: HasHashedPublicKey
        | Sequence[HasHashedPublicKey | RollingKeyPairSource]
        | RollingKeyPairSource,
    ) -> MaybeCoro[
        list[LocationReport] | dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]
    ]:
        """
        Fetch location history for :class:`HasHashedPublicKey`s and :class:`RollingKeyPairSource`s.

        Note that location history for devices is provided on a best-effort
        basis and may not be fully complete or stable. Multiple consecutive calls to this method
        may result in different location reports, especially for reports further in the past.
        However, each one of these reports is guaranteed to be in line with the data reported by
        Apple, and the most recent report will always be included in the results.

        Unless you really need to use this method, and use :meth:`fetch_location` instead.
        """
        raise NotImplementedError

    @overload
    @abstractmethod
    def fetch_location(
        self,
        keys: HasHashedPublicKey,
    ) -> MaybeCoro[LocationReport | None]: ...

    @overload
    @abstractmethod
    def fetch_location(
        self,
        keys: RollingKeyPairSource,
    ) -> MaybeCoro[LocationReport | None]: ...

    @overload
    @abstractmethod
    def fetch_location(
        self,
        keys: Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> MaybeCoro[
        dict[HasHashedPublicKey | RollingKeyPairSource, LocationReport | None] | None
    ]: ...

    @abstractmethod
    def fetch_location(
        self,
        keys: HasHashedPublicKey
        | Sequence[HasHashedPublicKey | RollingKeyPairSource]
        | RollingKeyPairSource,
    ) -> MaybeCoro[
        LocationReport
        | dict[HasHashedPublicKey | RollingKeyPairSource, LocationReport | None]
        | None
    ]:
        """
        Fetch location for :class:`HasHashedPublicKey`s.

        Returns a dictionary mapping :class:`HasHashedPublicKey`s to their location reports.
        """
        raise NotImplementedError

    @abstractmethod
    def get_anisette_headers(self) -> MaybeCoro[dict[str, str]]:
        """
        Retrieve a complete dictionary of Anisette headers.

        Utility method for :meth:`AnisetteProvider.get_headers` using this account's user/device ID.
        """
        raise NotImplementedError


class AsyncAppleAccount(BaseAppleAccount):
    """An async implementation of :meth:`BaseAppleAccount`."""

    # auth endpoints
    _ENDPOINT_GSA = "https://gsa.apple.com/grandslam/GsService2"
    _ENDPOINT_LOGIN_MOBILEME = "https://setup.icloud.com/setup/iosbuddy/loginDelegates"

    # 2fa auth endpoints
    _ENDPOINT_2FA_METHODS = "https://gsa.apple.com/auth"
    _ENDPOINT_2FA_SMS_REQUEST = "https://gsa.apple.com/auth/verify/phone"
    _ENDPOINT_2FA_SMS_SUBMIT = "https://gsa.apple.com/auth/verify/phone/securitycode"
    _ENDPOINT_2FA_TD_REQUEST = "https://gsa.apple.com/auth/verify/trusteddevice"
    _ENDPOINT_2FA_TD_SUBMIT = "https://gsa.apple.com/grandslam/GsService2/validate"

    # reports endpoints
    _ENDPOINT_REPORTS_FETCH = "https://gateway.icloud.com/findmyservice/v2/fetch"

    def __init__(
        self,
        anisette: BaseAnisetteProvider,
        *,
        state_info: AccountStateMapping | None = None,
        session: Optional[HttpSession] = None,
    ) -> None:
        """
        Initialize the apple account.

        :param anisette: An instance of :meth:`AsyncAnisetteProvider`.
        """
        super().__init__()

        self._anisette: BaseAnisetteProvider = anisette
        self._uid: str = state_info["ids"]["uid"] if state_info else str(uuid.uuid4())
        self._devid: str = state_info["ids"]["devid"] if state_info else str(uuid.uuid4())

        # TODO: combine, user/pass should be "all or nothing"  # noqa: TD002, TD003
        self._username: str | None = state_info["account"]["username"] if state_info else None
        self._password: str | None = state_info["account"]["password"] if state_info else None

        self._login_state: LoginState = (
            LoginState(state_info["login"]["state"]) if state_info else LoginState.LOGGED_OUT
        )
        self._login_state_data: dict = state_info["login"]["data"] if state_info else {}

        self._idms_pet: str | None = None

        self._account_info: _AccountInfo | None = (
            state_info["account"]["info"] if state_info else None
        )

        if session:
            self._http = session # Use provided session
            self._session_owner = False # We don't own it
        else:
            self._http = HttpSession() # Create our own
            self._session_owner = True # We own it

        self._reports: LocationReportsFetcher = LocationReportsFetcher(self)
        self._closed: bool = False
        self._cloudkit_manager: Optional[CloudKitManager] = None

        try:
            identity = KeychainUserIdentity.load_from_disk("identity.json")
        except Exception:
            machine_id = self._uid          # use the account's unique device ID
            model_id = "MacBookPro18,3"     # or any realistic device model string
            identity = KeychainUserIdentity(machine_id, model_id)  # or KeychainUserIdentity(machine_id, model_id) if required

        # Bind runtime context so identity.account / .anisette / .http are available
        identity.bind_context(self, self._anisette, self._http)

        # Store on the account for later use
        self._identity: KeychainUserIdentity = identity


    async def _get_cloudkit_manager(self) -> CloudKitManager:
        """Initializes and returns the CloudKitManager."""
        if self.login_state < LoginState.AUTHENTICATED:
            raise InvalidStateError(
                f"CloudKitManager requires AUTHENTICATED state or higher, "
                f"but state is {self.login_state.name}"
            )

        if self._cloudkit_manager is None:
            logger.debug("Creating new CloudKitManager instance.")
            if self._http is None:
                raise InvalidStateError("HTTP session not initialized.")
            if self._anisette is None:
                raise InvalidStateError("Anisette provider not initialized.")

            self._cloudkit_manager = CloudKitManager(
                account=self,
                anisette_provider=self._anisette,
                http_session=self._http
            )
            await self._cloudkit_manager._ensure_initialized()
        return self._cloudkit_manager

    def _set_login_state(
        self,
        state: LoginState,
        data: dict | None = None,
    ) -> LoginState:
        # clear account info if downgrading state (e.g. LOGGED_IN -> LOGGED_OUT)
        if state < self._login_state:
            logger.debug("Clearing cached account information")
            self._account_info = None

        logger.info("Transitioning login state: %s -> %s", self._login_state, state)
        self._login_state = state
        self._login_state_data = data or {}

        return state

    @property
    @override
    def login_state(self) -> LoginState:
        """See :meth:`BaseAppleAccount.login_state`."""
        return self._login_state

    @property
    @_require_login_state(
        LoginState.LOGGED_IN,
        LoginState.AUTHENTICATED,
        LoginState.REQUIRE_2FA,
    )
    @override
    def account_name(self) -> str | None:
        """See :meth:`BaseAppleAccount.account_name`."""
        return self._account_info["account_name"] if self._account_info else None

    @property
    @_require_login_state(
        LoginState.LOGGED_IN,
        LoginState.AUTHENTICATED,
        LoginState.REQUIRE_2FA,
    )
    @override
    def first_name(self) -> str | None:
        """See :meth:`BaseAppleAccount.first_name`."""
        return self._account_info["first_name"] if self._account_info else None

    @property
    @_require_login_state(
        LoginState.LOGGED_IN,
        LoginState.AUTHENTICATED,
        LoginState.REQUIRE_2FA,
    )
    @override
    def last_name(self) -> str | None:
        """See :meth:`BaseAppleAccount.last_name`."""
        return self._account_info["last_name"] if self._account_info else None

    @override
    def to_json(self, path: str | Path | None = None, /) -> AccountStateMapping:
        res: AccountStateMapping = {
            "type": "account",
            "ids": {"uid": self._uid, "devid": self._devid},
            "account": {
                "username": self._username,
                "password": self._password,
                "info": self._account_info,
            },
            "login": {
                "state": self._login_state.value,
                "data": self._login_state_data,
            },
            "anisette": self._anisette.to_json(),
        }

        return util.files.save_and_return_json(res, path)

    @classmethod
    @override
    def from_json(
        cls,
        val: str | Path | AccountStateMapping,
        /,
        *,
        anisette_libs_path: str | Path | None = None,
    ) -> AsyncAppleAccount:
        val = util.files.read_data_json(val)
        assert val["type"] == "account"

        try:
            ani_provider = get_provider_from_mapping(val["anisette"], libs_path=anisette_libs_path)
            return cls(ani_provider, state_info=val)
        except KeyError as e:
            msg = f"Failed to restore account data: {e}"
            raise ValueError(msg) from None

    @override
    async def close(self) -> None:
        """
        Close any sessions or other resources in use by this object.
        Should be called when the object will no longer be used.
        """
        if self._closed:
            return
        self._closed = True

        self._set_login_state(LoginState.LOGGED_OUT)

        # Dereference the CloudKitManager first, as it depends on _http
        if self._cloudkit_manager:
            logger.debug("Clearing CloudKitManager...")
            self._cloudkit_manager = None

        # Close anisette first, as per the existing comment
        try:
            await self._anisette.close()
        except Exception as e:
            logger.warning(f"Error closing anisette provider: {e}")

        # Now, close the HTTP session *if* we own it
        if self._session_owner and self._http:
            logger.debug("Closing owned HttpSession...")
            try:
                await self._http.close()
            except Exception as e:
                logger.warning(f"Error closing HTTP session: {e}")
            finally:
                self._http = None # Clear reference

    @_require_login_state(LoginState.LOGGED_OUT)
    @override
    async def login(self, username: str, password: str) -> LoginState:
        """See :meth:`BaseAppleAccount.login`."""
        # LOGGED_OUT -> (REQUIRE_2FA or AUTHENTICATED)
        new_state = await self._gsa_authenticate(username, password)
        if new_state == LoginState.REQUIRE_2FA:  # pass control back to handle 2FA
            return new_state

        # AUTHENTICATED -> LOGGED_IN
        return await self._login_mobileme()

    @_require_login_state(LoginState.REQUIRE_2FA)
    @override
    async def get_2fa_methods(self) -> Sequence[AsyncSecondFactorMethod]:
        """See :meth:`BaseAppleAccount.get_2fa_methods`."""
        methods: list[AsyncSecondFactorMethod] = []

        if self._account_info is None:
            return []

        if self._account_info["trusted_device_2fa"]:
            methods.append(AsyncTrustedDeviceSecondFactor(self))

        # sms
        auth_page = await self._sms_2fa_request("GET", self._ENDPOINT_2FA_METHODS)
        try:
            phone_numbers = _extract_phone_numbers(auth_page)
            methods.extend(
                AsyncSmsSecondFactor(
                    self,
                    number.get("id") or -1,
                    number.get("numberWithDialCode") or "-",
                )
                for number in phone_numbers
            )
        except RuntimeError:
            logger.warning("Unable to extract phone numbers from login page")

        return methods

    @_require_login_state(LoginState.REQUIRE_2FA)
    @override
    async def sms_2fa_request(self, phone_number_id: int) -> None:
        """See :meth:`BaseAppleAccount.sms_2fa_request`."""
        data = {"phoneNumber": {"id": phone_number_id}, "mode": "sms"}

        await self._sms_2fa_request(
            "PUT",
            self._ENDPOINT_2FA_SMS_REQUEST,
            data,
        )

    @_require_login_state(LoginState.REQUIRE_2FA)
    @override
    async def sms_2fa_submit(self, phone_number_id: int, code: str) -> LoginState:
        """See :meth:`BaseAppleAccount.sms_2fa_submit`."""
        data = {
            "phoneNumber": {"id": phone_number_id},
            "securityCode": {"code": str(code)},
            "mode": "sms",
        }

        await self._sms_2fa_request(
            "POST",
            self._ENDPOINT_2FA_SMS_SUBMIT,
            data,
        )

        # REQUIRE_2FA -> AUTHENTICATED
        new_state = await self._gsa_authenticate()
        if new_state != LoginState.AUTHENTICATED:
            msg = f"Unexpected state after submitting 2FA: {new_state}"
            raise UnhandledProtocolError(msg)

        # AUTHENTICATED -> LOGGED_IN
        return await self._login_mobileme()

    @_require_login_state(LoginState.REQUIRE_2FA)
    @override
    async def td_2fa_request(self) -> None:
        """See :meth:`BaseAppleAccount.td_2fa_request`."""
        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "text/x-xml-plist",
        }
        await self._sms_2fa_request(
            "GET",
            self._ENDPOINT_2FA_TD_REQUEST,
            headers=headers,
        )

    @_require_login_state(LoginState.REQUIRE_2FA)
    @override
    async def td_2fa_submit(self, code: str) -> LoginState:
        """See :meth:`BaseAppleAccount.td_2fa_submit`."""
        headers = {
            "security-code": code,
            "Content-Type": "text/x-xml-plist",
            "Accept": "text/x-xml-plist",
        }
        await self._sms_2fa_request(
            "GET",
            self._ENDPOINT_2FA_TD_SUBMIT,
            headers=headers,
        )

        # REQUIRE_2FA -> AUTHENTICATED
        new_state = await self._gsa_authenticate()
        if new_state != LoginState.AUTHENTICATED:
            msg = f"Unexpected state after submitting 2FA: {new_state}"
            raise UnhandledProtocolError(msg)

        # AUTHENTICATED -> LOGGED_IN
        return await self._login_mobileme()

    @_require_login_state(LoginState.LOGGED_IN)
    async def fetch_raw_reports(  # noqa: C901
        self,
        devices: list[tuple[list[str], list[str]]],
    ) -> list[LocationReport]:
        """Make a request for location reports, returning raw data."""
        logger.debug("Fetching raw reports for %d device(s)", len(devices))

        now = datetime.now(tz=timezone.utc)
        start_ts = int((now - timedelta(days=7)).timestamp()) * 1000
        end_ts = int(now.timestamp()) * 1000

        auth = (
            self._login_state_data["dsid"],
            self._login_state_data["mobileme_data"]["tokens"]["searchPartyToken"],
        )
        data = {
            "clientContext": {
                "clientBundleIdentifier": "com.apple.icloud.searchpartyuseragent",
                "policy": "foregroundClient",
            },
            "fetch": [
                {
                    "ownedDeviceIds": [],
                    "keyType": 1,
                    "startDate": start_ts,
                    "startDateSecondary": start_ts,
                    "endDate": end_ts,
                    "primaryIds": device_keys[0],
                    "secondaryIds": device_keys[1],
                }
                for device_keys in devices
            ],
        }

        async def _do_request() -> util.http.HttpResponse:
            # bandaid fix for https://github.com/malmeloo/FindMy.py/issues/185
            # Symptom: HTTP 200 but empty response
            # Remove when real issue fixed
            retry_counter = 1
            while True:
                if self._http is None:
                    raise InvalidStateError("Account session is closed.")
                resp = await self._http.post(
                    self._ENDPOINT_REPORTS_FETCH,
                    auth=auth,
                    headers=await self.get_anisette_headers(),
                    json=data,
                )

                if resp.status_code != 200 or resp.text().strip():
                    return resp

                logger.warning(
                    "Empty response received when fetching reports, retrying (%d/3)",
                    retry_counter,
                )
                retry_counter += 1

                if retry_counter > 3:
                    logger.warning("Max retries reached, returning empty response")
                    return resp

                await asyncio.sleep(2)

        r = await _do_request()
        if r.status_code == 401:
            logger.info("Got 401 while fetching reports, redoing login")

            new_state = await self._gsa_authenticate()
            if new_state != LoginState.AUTHENTICATED:
                msg = f"Unexpected login state after reauth: {new_state}. Please log in again."
                raise UnauthorizedError(msg)
            await self._login_mobileme()

            r = await _do_request()

        if r.status_code == 401:
            msg = "Not authorized to fetch reports."
            raise UnauthorizedError(msg)

        try:
            resp = r.json()
        except json.JSONDecodeError:
            resp = {}
        if not r.ok or resp.get("acsnLocations", {}).get("statusCode") != "200":
            msg = f"Failed to fetch reports: {resp.get('statusCode')}"
            raise UnhandledProtocolError(msg)

        # parse reports
        reports: list[LocationReport] = []
        for key_reports in resp.get("acsnLocations", {}).get("locationPayload", []):
            hashed_adv_key_bytes = base64.b64decode(key_reports["id"])

            for report in key_reports.get("locationInfo", []):
                payload = base64.b64decode(report)
                loc_report = LocationReport(payload, hashed_adv_key_bytes)

                reports.append(loc_report)

        return reports

    @overload
    async def fetch_location_history(
        self,
        keys: HasHashedPublicKey,
    ) -> list[LocationReport]: ...

    @overload
    async def fetch_location_history(
        self,
        keys: RollingKeyPairSource,
    ) -> list[LocationReport]: ...

    @overload
    async def fetch_location_history(
        self,
        keys: Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]: ...

    @override
    async def fetch_location_history(
        self,
        keys: HasHashedPublicKey
        | Sequence[HasHashedPublicKey | RollingKeyPairSource]
        | RollingKeyPairSource,
    ) -> (
        list[LocationReport] | dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]
    ):
        """See `BaseAppleAccount.fetch_location_history`."""
        return await self._reports.fetch_location_history(keys)

    @overload
    async def fetch_location(
        self,
        keys: HasHashedPublicKey,
    ) -> LocationReport | None: ...

    @overload
    async def fetch_location(
        self,
        keys: RollingKeyPairSource,
    ) -> LocationReport | None: ...

    @overload
    async def fetch_location(
        self,
        keys: Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> dict[HasHashedPublicKey | RollingKeyPairSource, LocationReport | None]: ...

    @_require_login_state(LoginState.LOGGED_IN)
    @override
    async def fetch_location(
        self,
        keys: HasHashedPublicKey
        | RollingKeyPairSource
        | Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> (
        LocationReport
        | dict[HasHashedPublicKey | RollingKeyPairSource, LocationReport | None]
        | None
    ):
        """See :meth:`BaseAppleAccount.fetch_location`."""
        hist = await self.fetch_location_history(keys)
        if isinstance(hist, list):
            return sorted(hist)[-1] if hist else None

        return {dev: sorted(reports)[-1] if reports else None for dev, reports in hist.items()}

    @_require_login_state(LoginState.LOGGED_OUT, LoginState.REQUIRE_2FA, LoginState.LOGGED_IN)
    async def _gsa_authenticate(
        self,
        username: str | None = None,
        password: str | None = None,
    ) -> LoginState:
        # use stored values for re-authentication
        self._username = username or self._username
        self._password = password or self._password

        logger.info("Attempting authentication for user %s", self._username)

        if not self._username or not self._password:
            msg = "No username or password specified"
            raise ValueError(msg)

        logger.debug("Starting authentication with username")

        usr = srp.User(self._username, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        _, a2k = usr.start_authentication()
        r = await self._gsa_request(
            {"A2k": a2k, "u": self._username, "ps": ["s2k", "s2k_fo"], "o": "init"},
        )

        logger.debug("Verifying response to auth request")

        if r["Status"].get("ec") != 0:
            msg = "Email verification failed: " + r["Status"].get("em")
            raise InvalidCredentialsError(msg)
        sp = r.get("sp")
        if not isinstance(sp, str) or sp not in {"s2k", "s2k_fo"}:
            msg = f"This implementation only supports s2k and sk2_fo. Server returned {sp}"
            raise UnhandledProtocolError(msg)

        logger.debug("Attempting password challenge")

        usr.p = util.crypto.encrypt_password(self._password, r["s"], r["i"], sp)
        m1 = usr.process_challenge(r["s"], r["B"])
        if m1 is None:
            msg = "Failed to process challenge"
            raise UnhandledProtocolError(msg)
        r = await self._gsa_request(
            {"c": r["c"], "M1": m1, "u": self._username, "o": "complete"},
        )

        logger.debug("Verifying password challenge response")

        if r["Status"].get("ec") != 0:
            msg = "Password authentication failed: " + r["Status"].get("em")
            raise InvalidCredentialsError(msg)
        usr.verify_session(r.get("M2"))
        if not usr.authenticated():
            msg = "Failed to verify session"
            raise UnhandledProtocolError(msg)

        logger.debug("Decrypting SPD data in response")

        spd = util.parsers.decode_plist(
            util.crypto.decrypt_spd_aes_cbc(
                usr.get_session_key() or b"",
                r["spd"],
            ),
        )

        logger.debug("Received account information")
        self._account_info = cast(
            "_AccountInfo",
            {
                "account_name": spd.get("acname"),
                "first_name": spd.get("fn"),
                "last_name": spd.get("ln"),
                "trusted_device_2fa": False,
            },
        )

        au = r["Status"].get("au")
        if au in ("secondaryAuth", "trustedDeviceSecondaryAuth"):
            logger.info("Detected 2FA requirement: %s", au)

            self._account_info["trusted_device_2fa"] = au == "trustedDeviceSecondaryAuth"

            return self._set_login_state(
                LoginState.REQUIRE_2FA,
                {"adsid": spd["adsid"], "idms_token": spd["GsIdmsToken"]},
            )
        if au is None:
            logger.info("GSA authentication successful")

            idms_pet = spd.get("t", {}).get("com.apple.gs.idms.pet", {}).get("token", "")

            # Save idms_pet token for masterkey escrow
            self._idms_pet = idms_pet

            return self._set_login_state(
                LoginState.AUTHENTICATED,
                {"idms_pet": idms_pet, "adsid": spd["adsid"]},
            )

        msg = f"Unknown auth value: {au}"
        raise UnhandledProtocolError(msg)

    @_require_login_state(LoginState.AUTHENTICATED)
    async def _login_mobileme(self) -> LoginState:
        logger.info("Logging into com.apple.mobileme")
        data = plistlib.dumps(
            {
                "apple-id": self._username,
                "delegates": {"com.apple.mobileme": {}},
                "password": self._login_state_data["idms_pet"],
                "client-id": self._uid,
            },
        )

        headers = {
            "X-Apple-ADSID": self._login_state_data["adsid"],
            "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
            "X-Mme-Client-Info": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8>"
            " <com.apple.AOSKit/282 (com.apple.accountsd/113)>",
            # Ensure get_anisette_headers() returns a dictionary
            **(await self.get_anisette_headers()) 
        }
        # Note: Added ** to merge the anisette headers dictionary

        # --- STEP 2: Log Outgoing Headers ---
        logger.debug("--- Outgoing MobileMe Login Request Headers ---")
        try:
            # Use json.dumps for pretty printing the headers dictionary
            logger.debug(json.dumps(headers, indent=2))
        except Exception as e:
            logger.debug(f"Could not format headers for logging: {e}")
        logger.debug("---------------------------------------------")
        # --- End STEP 2 ---

        # Existing request call using the internal _http session
        if self._http is None:
            raise InvalidStateError("Account session is closed.")
        resp = await self._http.post(
            self._ENDPOINT_LOGIN_MOBILEME,
            auth=(self._username or "", self._login_state_data["idms_pet"]),
            data=data, # Send raw plist bytes
            headers=headers,
        )

        # --- STEP 3: Log Raw Response ---
        logger.info(f"Raw MobileMe HTTP Response Status: {resp.status_code}")
        logger.info("--- Raw MobileMe HTTP Response Body (Bytes) START ---")
        try:
            # --- CORRECTED LINE: Use await resp.read() ---
            raw_body_bytes = resp._content
            # Log the raw bytes (e.g., first 500 bytes for brevity)
            logger.info(f"Raw Bytes (first 500): {raw_body_bytes[:500]!r}...")
            # Optionally log the decoded text if useful, but be aware it might fail/corrupt binary data
            try:
                logger.info(f"Attempting text decode:\n{raw_body_bytes.decode('utf-8', errors='replace')}")
            except Exception:
                 logger.warning("Could not decode raw bytes as UTF-8 for logging.")
        except Exception as read_error:
            logger.error(f"Error reading response body: {read_error}")
            raw_body_bytes = b"" # Set to empty bytes on error
        logger.info("--- Raw MobileMe HTTP Response Body (Bytes) END ---")

        if resp.status_code != 200:
            logger.error(f"MobileMe login failed with status {resp.status_code}. Raw body logged above.")
            return self._set_login_state(LoginState.LOGGED_OUT)

        # --- Check if raw_body_bytes is empty before parsing ---
        if not raw_body_bytes:
             logger.error("Response body is empty, cannot parse plist.")
             return self._set_login_state(LoginState.LOGGED_OUT) # Or raise error

        try:
            # --- CORRECTED LINE: Parse using the awaited bytes ---
            response_data = plistlib.loads(raw_body_bytes)
        except Exception as parse_error:
            logger.error(f"Failed to parse plist response: {parse_error}")
            logger.error("Raw response bytes were logged above.")
            return self._set_login_state(LoginState.LOGGED_OUT) # Or raise

        # --- STEP 4: Log Parsed Data and Check Keys (Remains the same) ---
        # ... (the rest of the logging and key checking code from Step 4) ...

        # Ensure correct data is extracted for the final state
        mobileme_delegate_data = response_data.get("delegates", {}).get("com.apple.mobileme", {})
        config_dict = mobileme_delegate_data.get("config") # Extract config from delegate
        service_data = mobileme_delegate_data.get("service-data", {})

        # Check status again after parsing
        status = mobileme_delegate_data.get("status", response_data.get("status"))
        if status != 0:
            status_message = mobileme_delegate_data.get("status-message", response_data.get("status-message"))
            logger.error(f"MobileMe login reported failure status {status}: {status_message}")
            raise UnhandledProtocolError(f"com.apple.mobileme login failed with status {status}: {status_message}")

        return self._set_login_state(
            LoginState.LOGGED_IN,
            {
                "dsid": response_data.get("dsid"),
                "mobileme_data": service_data,
                "config": config_dict
            }
        )

    async def _sms_2fa_request(
        self,
        method: str,
        url: str,
        data: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
    ) -> str:
        adsid = self._login_state_data["adsid"]
        idms_token = self._login_state_data["idms_token"]
        identity_token = base64.b64encode((adsid + ":" + idms_token).encode()).decode()

        headers = headers or {}
        headers.update(
            {
                "User-Agent": "Xcode",
                "Accept-Language": "en-us",
                "X-Apple-Identity-Token": identity_token,
            },
        )
        headers.update(await self.get_anisette_headers())

        if self._http is None:
            raise InvalidStateError("Account session is closed.")
        r = await self._http.request(
            method,
            url,
            json=data,
            headers=headers,
        )
        if not r.ok:
            msg = f"SMS 2FA request failed: {r.status_code}"
            raise UnhandledProtocolError(msg)

        return r.text()

    async def _gsa_request(self, parameters: dict) -> dict:
        """Helper for making GrandSlam Authentication requests."""

        # First, ensure anisette data is populated by calling get_headers
        # This will trigger the underlying py-anisette call if not already done.
        anisette_headers = await self._anisette.get_headers(self._uid, self._devid)

        # Now, get the full hardware config dictionary
        config = self._anisette.get_hardware_config_dict()

        try:
            # Extract the required data from the config dict
            cpd = config["cpd"]
            client_info = config["X-Mme-Client-Info"]
        except KeyError as e:
            logger.error(f"Anisette data is missing required GSA key: {e}")
            raise PushError(f"Anisette provider data incomplete, missing {e}") from e

        body = {"Header": {"Version": "1.0.1"}, "Request": {"cpd": cpd, **parameters}}

        # Build headers, merging standard ones with all anisette headers
        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
            **anisette_headers, # Add all anisette headers
            "X-MMe-Client-Info": client_info, # Ensure this one is correct
        }

        if self._http is None:
            raise InvalidStateError("Account is closed.")

        resp: util.http.HttpResponse = await self._http.post(self._ENDPOINT_GSA, headers=headers, data=plistlib.dumps(body))
        if not resp.ok:
            raise UnhandledProtocolError(f"GSA request error: {resp.status_code}")
        return resp.plist()["Response"]

    async def _get_mme_token(self, token_key: str) -> str:
        """Helper to get a specific MME token, refreshing if needed."""
        if self.login_state != LoginState.LOGGED_IN:
            raise InvalidStateError(f"Token fetch requires LOGGED_IN state, but state is {self.login_state.name}")

        # Safely access nested dictionary structure
        token = self._login_state_data.get("mobileme_data", {}).get("tokens", {}).get(token_key)

        if not token:
            logger.warning(f"MME token '{token_key}' not found in state, attempting refresh...")
            # Trigger re-login to refresh tokens
            auth_state = await self._gsa_authenticate() # Re-auth uses stored creds
            if auth_state != LoginState.AUTHENTICATED:
                raise PushError(f"Re-authentication failed or requires 2FA during token refresh. State: {auth_state.name}")

            await self._login_mobileme()

            token = self._login_state_data.get("mobileme_data", {}).get("tokens", {}).get(token_key)
            if not token:
                raise PushError(f"Failed to get MME token '{token_key}' even after refresh.")

        return token

    @override
    async def get_anisette_headers(
        self
    ) -> dict[str, str]:
        """See :meth:`BaseAppleAccount.get_anisette_headers`."""
        return await self._anisette.get_headers(self._uid, self._devid)

    @property
    def idms_pet(self) -> str | None:
        """
        The GsIdmsToken, required for escrow operations.
        This is only available after a successful GSA authentication
        and may be cleared on subsequent logins.
        """
        return self._idms_pet
    
    @property
    def cloudkit_manager(self) -> CloudKitManager:
        """Lazily get or create a CloudKitManager instance."""
        if not hasattr(self, "_cloudkit_manager") or self._cloudkit_manager is None:
            from findmy.keychain.cloudkit_manager import CloudKitManager
            self._cloudkit_manager = CloudKitManager(
                account=self,
                anisette_provider=self._anisette,
                http_session=self._http or HttpSession()
            )
        return self._cloudkit_manager

    async def invoke_cuttlefish(
        self,
        function_name: str,
        request: Message,
        response_cls: type[Message],
    ) -> Message:
        """
        Invokes a Cuttlefish CloudKit function using CloudKit's FunctionInvokeRequest.

        Args:
            function_name: Name of the Cuttlefish function (e.g., "establish", "joinWithVoucher").
            request: The request protobuf to serialize and send.
            response_cls: The response protobuf class to parse into.

        Returns:
            An instance of response_cls.
        """
        from findmy.keychain.cloudkit_pb2 import FunctionInvokeRequest  # local import to avoid cycles

        logger.info(f"[Cuttlefish] Invoking function: {function_name}")

        try:
            # Construct the CloudKit FunctionInvokeRequest
            function_request = FunctionInvokeRequest()
            function_request.name = f"com.apple.security.keychain.{function_name}"
            function_request.parameters = request.SerializeToString()
            function_request.service = "com.apple.security.keychain"

            # Actually send this request via CloudKitManager
            result_bytes = await self.cloudkit_manager.function_invoke(function_request)

            # Parse into the provided response protobuf class
            response = response_cls()
            response.ParseFromString(bytes(result_bytes))  # enforce bytes not bytearray
            return response

        except Exception as e:
            logger.error(f"Failed to invoke Cuttlefish function '{function_name}': {e}")
            raise PushError(f"Cuttlefish invoke error: {e}")



class AppleAccount(BaseAppleAccount):
    """
    A sync implementation of :meth:`BaseappleAccount`.

    Uses :meth:`AsyncappleAccount` internally.
    """

    def __init__(
        self,
        anisette: BaseAnisetteProvider,
        *,
        state_info: AccountStateMapping | None = None,
        session: Optional[HttpSession] = None,
    ) -> None:
        """See :meth:`AsyncAppleAccount.__init__`."""
        self._asyncacc = AsyncAppleAccount(anisette=anisette, state_info=state_info, session=session)

        try:
            self._evt_loop = asyncio.get_running_loop()
        except RuntimeError:
            self._evt_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._evt_loop)

        super().__init__(self._evt_loop)

    @override
    async def close(self) -> None:
        """See :meth:`AsyncAppleAccount.close`."""
        await self._asyncacc.close()

    @property
    @override
    def login_state(self) -> LoginState:
        """See :meth:`AsyncAppleAccount.login_state`."""
        return self._asyncacc.login_state

    @property
    @override
    def account_name(self) -> str | None:
        """See :meth:`AsyncAppleAccount.login_state`."""
        return self._asyncacc.account_name

    @property
    @override
    def first_name(self) -> str | None:
        """See :meth:`AsyncAppleAccount.first_name`."""
        return self._asyncacc.first_name

    @property
    @override
    def last_name(self) -> str | None:
        """See :meth:`AsyncAppleAccount.last_name`."""
        return self._asyncacc.last_name

    @override
    def to_json(self, dst: str | Path | None = None, /) -> AccountStateMapping:
        return self._asyncacc.to_json(dst)

    @classmethod
    @override
    def from_json(
        cls,
        val: str | Path | AccountStateMapping,
        /,
        *,
        anisette_libs_path: str | Path | None = None,
    ) -> AppleAccount:
        val = util.files.read_data_json(val)
        try:
            ani_provider = get_provider_from_mapping(val["anisette"], libs_path=anisette_libs_path)
            return cls(ani_provider, state_info=val)
        except KeyError as e:
            msg = f"Failed to restore account data: {e}"
            raise ValueError(msg) from None

    @override
    def login(self, username: str, password: str) -> LoginState:
        """See :meth:`AsyncAppleAccount.login`."""
        coro = self._asyncacc.login(username, password)
        return self._evt_loop.run_until_complete(coro)

    @override
    def get_2fa_methods(self) -> Sequence[SyncSecondFactorMethod]:
        """See :meth:`AsyncAppleAccount.get_2fa_methods`."""
        coro = self._asyncacc.get_2fa_methods()
        methods = self._evt_loop.run_until_complete(coro)

        res = []
        for m in methods:
            if isinstance(m, AsyncSmsSecondFactor):
                res.append(SyncSmsSecondFactor(self, m.phone_number_id, m.phone_number))
            elif isinstance(m, AsyncTrustedDeviceSecondFactor):
                res.append(SyncTrustedDeviceSecondFactor(self))
            else:
                msg = (
                    f"Failed to cast 2FA object to sync alternative: {m}."
                    f" This is a bug, please report it."
                )
                raise TypeError(msg)

        return res

    @override
    def sms_2fa_request(self, phone_number_id: int) -> None:
        """See :meth:`AsyncAppleAccount.sms_2fa_request`."""
        coro = self._asyncacc.sms_2fa_request(phone_number_id)
        return self._evt_loop.run_until_complete(coro)

    @override
    def sms_2fa_submit(self, phone_number_id: int, code: str) -> LoginState:
        """See :meth:`AsyncAppleAccount.sms_2fa_submit`."""
        coro = self._asyncacc.sms_2fa_submit(phone_number_id, code)
        return self._evt_loop.run_until_complete(coro)

    @override
    def td_2fa_request(self) -> None:
        """See :meth:`AsyncAppleAccount.td_2fa_request`."""
        coro = self._asyncacc.td_2fa_request()
        return self._evt_loop.run_until_complete(coro)

    @override
    def td_2fa_submit(self, code: str) -> LoginState:
        """See :meth:`AsyncAppleAccount.td_2fa_submit`."""
        coro = self._asyncacc.td_2fa_submit(code)
        return self._evt_loop.run_until_complete(coro)

    @overload
    def fetch_location_history(
        self,
        keys: HasHashedPublicKey,
    ) -> list[LocationReport]: ...

    @overload
    def fetch_location_history(
        self,
        keys: RollingKeyPairSource,
    ) -> list[LocationReport]: ...

    @overload
    def fetch_location_history(
        self,
        keys: Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]: ...

    @override
    def fetch_location_history(
        self,
        keys: HasHashedPublicKey
        | Sequence[HasHashedPublicKey | RollingKeyPairSource]
        | RollingKeyPairSource,
    ) -> (
        list[LocationReport] | dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]
    ):
        """See `BaseAppleAccount.fetch_location_history`."""
        coro = self._asyncacc.fetch_location_history(keys)
        return self._evt_loop.run_until_complete(coro)

    @overload
    def fetch_location(
        self,
        keys: HasHashedPublicKey,
    ) -> LocationReport | None: ...

    @overload
    def fetch_location(
        self,
        keys: RollingKeyPairSource,
    ) -> LocationReport | None: ...

    @overload
    def fetch_location(
        self,
        keys: Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> dict[HasHashedPublicKey | RollingKeyPairSource, LocationReport | None]: ...

    @override
    def fetch_location(
        self,
        keys: HasHashedPublicKey
        | RollingKeyPairSource
        | Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> (
        LocationReport
        | dict[HasHashedPublicKey | RollingKeyPairSource, LocationReport | None]
        | None
    ):
        """See :meth:`BaseAppleAccount.fetch_location`."""
        hist = self.fetch_location_history(keys)
        if isinstance(hist, list):
            return sorted(hist)[-1] if hist else None

        return {dev: sorted(reports)[-1] if reports else None for dev, reports in hist.items()}

    @override
    def get_anisette_headers(
        self,
    ) -> dict[str, str]:
        """See :meth:`AsyncAppleAccount.get_anisette_headers`."""
        coro = self._asyncacc.get_anisette_headers()
        return self._evt_loop.run_until_complete(coro)
