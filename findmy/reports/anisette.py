# findmy/reports/anisette.py
import asyncio
import base64
import logging
import re
from abc import abstractmethod
from functools import partial
from pathlib import Path
from typing import (
    Any,
    ClassVar,
    Dict,
    Generic,
    Optional,
    Type,
    TypeVar,
    cast,
)

from typing_extensions import override

from findmy.errors import PushError
from findmy.reports.state import (
    AnisetteMapping,
    Closable,
    Serializable,
    State,
    StateError,
)

logger = logging.getLogger(__name__)

try:
    from anisette import Anisette
except ImportError:
    logger.debug("py-anisette not installed. LocalAnisetteProvider will not be available.")
    Anisette = None  # type: ignore


class LocalAnisetteMapping(AnisetteMapping):
    url: str
    data: Optional[bytes]
    path: Optional[str]


# TypeVar for the specific AnisetteMapping
M = TypeVar("M", bound=AnisetteMapping)


class BaseAnisetteProvider(Serializable[M], Closable, Generic[M]):
    """Base class for providing anisette headers."""

    _state: State[M]
    _ani_data: Dict[str, Any]  # Populated by subclass

    def __init__(self, state: State[M]) -> None:
        self._state = state
        self._ani_data = {}

    async def get_headers(
        self, user_id: str, device_id: str
    ) -> dict[str, str]:
        """
        Fetches anisette headers.
        Subclasses must populate self._ani_data before calling this.
        """
        if not self._ani_data:
            raise StateError(
                "self._ani_data not populated by provider. "
                "Subclass implementation is incorrect."
            )

        # Extract only string headers
        headers = {}
        for k, v in self._ani_data.items():
            if isinstance(v, str) and (
                k.startswith("X-") or k in ("Authorization", "Content-Type", "Accept")
            ):
                headers[k] = v
        return headers

    @override
    async def close(self) -> None:
        """Closes any open resources."""
        pass

    # --- Methods from Implementation Plan ---
    @abstractmethod
    async def get_os_version_and_build(self) -> str:
        """Gets the OS version and build string, e.g., '15.1;21B74'."""
        ...

    @abstractmethod
    async def get_product_name(self) -> str:
        """Gets the device product name, e.g., 'iPhone13,2'."""
        ...

    @abstractmethod
    async def get_serial_number(self) -> str:
        """Gets the device serial number."""
        ...

    @abstractmethod
    def get_hardware_config_dict(self) -> Dict[str, Any]:
        """
        Gets the full anisette data dictionary.
        Return type is Dict[str, Any], not dict[str, str].
        """
        ...


class LocalAnisetteProvider(BaseAnisetteProvider[LocalAnisetteMapping]):
    """Provides anisette headers using the local py-anisette library."""

    Anisette: ClassVar[Optional[Type]] = Anisette
    _ani: Optional[Any]  # This is the Anisette object from py-anisette
    _loop: Optional[asyncio.AbstractEventLoop]

    def __init__(self, state: State[LocalAnisetteMapping]) -> None:
        if not self.Anisette:
            raise StateError(
                "py-anisette is not installed. "
                "Please install findmy-py[anisette] to use LocalAnisetteProvider."
            )
        super().__init__(state)
        self._ani = None
        self._loop = None

    async def _get_loop(self) -> asyncio.AbstractEventLoop:
        if not self._loop:
            self._loop = asyncio.get_event_loop()
        return self._loop

    @property
    def _path(self) -> Optional[Path]:
        path_str = self._state.get("path")
        return Path(path_str) if path_str else None

    @property
    def _data(self) -> Optional[bytes]:
        return self._state.get("data")

    async def _get_ani(self) -> Any:
        if self._ani:
            return self._ani

        loop = await self._get_loop()
        logger.debug(
            f"Loading anisette data from path: {self._path}, "
            f"data length: {len(self._data or b'')}"
        )
        
        # This is a known Pylance false positive.
        self._ani = await loop.run_in_executor(
            None,
            self.Anisette,  # type: ignore
            str(self._path) if self._path else None,
            self._data,
        )
        return self._ani

    @override
    async def get_headers(
        self, user_id: str, device_id: str
    ) -> dict[str, str]:
        """
        Fetches anisette headers from the local library.
        Implements plan.
        """
        ani = await self._get_ani()
        loop = await self._get_loop()

        # 1. Fetch data and store it locally
        # This is a blocking call
        self._ani_data = await loop.run_in_executor(
            None, partial(ani.get_data, user_id, device_id)
        )

        # 2. Call super() to extract headers
        return await super().get_headers(user_id, device_id)

    @override
    async def close(self) -> None:
        """Closes the anisette provider."""
        if self._ani:
            # The Anisette object from py-anisette has no .close() method.
            self._ani = None
            logger.debug("Closed local anisette provider.")
        await super().close()

    @override
    def to_json(self) -> LocalAnisetteMapping:
        """Serializes the anisette state."""
        if not self._ani:
            # Not initialized, just return current state
            return self._state.to_json()

        # The Anisette object has no .save() method.
        # We rely on the state object being saved externally.
        logger.debug("Serializing LocalAnisetteProvider state.")
        
        return self._state.to_json()

    @override
    @classmethod
    def from_json(cls, state: LocalAnisetteMapping) -> "LocalAnisetteProvider":
        """Deserializes the anisette state."""
        return cls(State(state))

    # --- Implementation of new methods ---

    def _parse_client_info(self) -> Dict[str, str]:
        """Helper to parse X-Mme-Client-Info header."""
        if "X-Mme-Client-Info" not in self._ani_data:
            logger.warning("X-Mme-Client-Info not in anisette data.")
            return {}
        
        client_info = str(self._ani_data["X-Mme-Client-Info"])
        # Example: <iPhone13,2;15.1;21B74>
        match = re.match(r"<([^;]+);([^;]+);([^>]+)>", client_info)
        if match:
            return {
                "product_name": match.group(1),
                "os_version": match.group(2),
                "build": match.group(3),
            }
        logger.warning(f"Could not parse X-Mme-Client-Info: {client_info}")
        return {}

    @override
    async def get_os_version_and_build(self) -> str:
        """Gets the OS version and build string, e.g., '15.1;21B74'."""
        info = self._parse_client_info()
        if info.get("os_version") and info.get("build"):
            return f"{info['os_version']};{info['build']}"
        
        # Fallback
        if "X-Mme-Client-Info" in self._ani_data:
            return str(self._ani_data["X-Mme-Client-Info"])
        
        raise PushError("Could not determine OS version from anisette data.")

    @override
    async def get_product_name(self) -> str:
        """Gets the device product name, e.g., 'iPhone13,2'."""
        info = self._parse_client_info()
        name = info.get("product_name")
        if name:
            return name
        
        raise PushError("Could not determine product name from anisette data.")

    @override
    async def get_serial_number(self) -> str:
        """Generates a mock serial number as per plan."""
        if "X-Apple-I-MD-M" in self._ani_data:
            # Use part of the machine-data hash as a mock serial
            md_m = str(self._ani_data["X-Apple-I-MD-M"])
            
            # Get 12 chars, URL-safe base64
            mock_serial = (
                base64.urlsafe_b64encode(md_m.encode("utf-8"))
                .decode("utf-8")
                .replace("=", "")[:12]
                .upper()
            )
            return mock_serial
        
        logger.warning("X-Apple-I-MD-M not in anisette data, using generic serial.")
        return "C02FMYNDMYPY"  # Generic fallback

    @override
    def get_hardware_config_dict(self) -> Dict[str, Any]:
        """
        Gets the full anisette data dictionary.
        Implements plan.
        """
        return cast(Dict[str, Any], self._ani_data)

def get_provider_from_mapping(
    mapping: AnisetteMapping,
    libs_path: Any = None, # libs_path is unused but kept for compatibility
) -> BaseAnisetteProvider[Any]:
    """
    Factory function to get an AnisetteProvider from a state mapping.
    """
    # We only have one provider type for now.
    # In the future, this could check mapping["provider_id"] or similar.
    
    # We must cast the base mapping to the specific type our provider needs.
    local_mapping = cast(LocalAnisetteMapping, mapping)
    
    # Ensure default values are present if loading from an older state
    local_mapping.setdefault("url", "")
    local_mapping.setdefault("data", None)
    local_mapping.setdefault("path", None)
    
    return LocalAnisetteProvider(State(local_mapping))