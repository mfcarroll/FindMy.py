# findmy/reports/anisette.py
"""Module for Anisette header providers."""

from __future__ import annotations

import asyncio
import base64
import locale
import logging
import time
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
# CHANGED: Added Dict, Tuple, Optional, cast
from typing import BinaryIO, Literal, TypedDict, Union, Dict, Tuple, Optional, cast

# Uses the original anisette library
from anisette import Anisette, AnisetteHeaders
from typing_extensions import override

from findmy import util
# FIXED: Import PushError
from findmy.errors import PushError
# FIXED: Import abc submodule correctly
from findmy.util import abc as util_abc
# FIXED: Import http submodule correctly
from findmy.util import http as util_http


logger = logging.getLogger(__name__)


# --- AnisetteMapping TypedDicts ---
class RemoteAnisetteMapping(TypedDict):
    """JSON mapping representing state of a remote Anisette provider."""

    type: Literal["aniRemote"]
    url: str


class LocalAnisetteMapping(TypedDict):
    """JSON mapping representing state of a local Anisette provider."""

    type: Literal["aniLocal"]
    prov_data: str | None


AnisetteMapping = Union[RemoteAnisetteMapping, LocalAnisetteMapping]
# --- End AnisetteMapping ---


def get_provider_from_mapping(
    mapping: AnisetteMapping,
    *,
    libs_path: str | Path | None = None,
) -> RemoteAnisetteProvider | LocalAnisetteProvider:
    """Get the correct Anisette provider instance from saved JSON data."""
    if mapping["type"] == "aniRemote":
        # FIXED: Call correct from_json
        return RemoteAnisetteProvider.from_json(mapping)
    if mapping["type"] == "aniLocal":
        # FIXED: Call correct from_json
        return LocalAnisetteProvider.from_json(mapping, libs_path=libs_path)
    msg = f"Unknown anisette type: {mapping['type']}"
    raise ValueError(msg)


# FIXED: Inherit from util_abc
class BaseAnisetteProvider(util_abc.Closable, util_abc.Serializable[AnisetteMapping], ABC):
    """Base abstract class for Anisette providers."""

    _ani_headers: Optional[AnisetteHeaders] = None

    def __init__(self) -> None:
        super().__init__()
        self._ani_headers = None

    @abstractmethod
    async def close(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def to_json(self, dst: str | Path | None = None, /) -> AnisetteMapping:
        raise NotImplementedError

    # FIXED: Correct signature to match base Serializable class
    @classmethod
    @abstractmethod
    def from_json(
        cls,
        val: AnisetteMapping | str | Path,
        /,
        *,
        libs_path: str | Path | None = None,
    ) -> BaseAnisetteProvider:
        raise NotImplementedError

    @abstractmethod
    async def get_headers(
        self,
        user_id: str,
        device_id: str,
        serial: str = "0",
        with_client_info: bool = False,
    ) -> dict[str, str]:
        """
        Get the base Anisette headers.
        Implementations should fetch data into self._ani_headers.
        """
        if self._ani_headers is None:
            raise RuntimeError("Anisette headers not fetched by provider implementation.")

        headers = dict(self._ani_headers) # Make a copy
        if not with_client_info:
           headers.pop("X-MMe-Client-Info", None)

        return headers

    @property
    def otp(self) -> str:
        """Get the 'X-Apple-I-MD' value."""
        if self._ani_headers is None:
             raise RuntimeError("Anisette data not fetched. Call get_headers() first.")
        machine = self._ani_headers.get("X-Apple-I-MD")
        if machine is None:
            logger.warning("X-Apple-I-MD header not found! Returning fallback...")
        return machine or ""

    @property
    def machine(self) -> str:
        """Get the 'X-Apple-I-MD-M' value."""
        if self._ani_headers is None:
             raise RuntimeError("Anisette data not fetched. Call get_headers() first.")
        machine = self._ani_headers.get("X-Apple-I-MD-M")
        if machine is None:
            logger.warning("X-Apple-I-MD-M header not found! Returning fallback...")
        return machine or ""

    # --- ADDED ABSTRACT METHODS ---
    @abstractmethod
    async def get_os_version_and_build(self) -> Tuple[str, str]:
        """
        Returns a tuple of (OS_Version, OS_Build_Number)
        e.g., ("14.4.1", "23E224")
        """
        raise NotImplementedError

    @abstractmethod
    async def get_product_name(self) -> str:
        """
        Returns the product name, e.g., "MacBookPro13,2"
        """
        raise NotImplementedError

    @abstractmethod
    async def get_serial_number(self) -> str:
        """
        Returns the device's serial number (may be mocked).
        """
        raise NotImplementedError

    @abstractmethod
    async def get_anisette_data_dict(self) -> Dict:
        """
        Returns a dictionary of all available anisette data fields (primarily headers).
        """
        raise NotImplementedError
    # --- END ADDED ABSTRACT METHODS ---


class RemoteAnisetteProvider(BaseAnisetteProvider):
    """Anisette provider using a remote server."""
    def __init__(self, url: str) -> None:
        super().__init__()
        self._url = url
        # FIXED: Use correct module alias
        self._http = util_http.HttpSession()

    # FIXED: Added override
    @override
    async def close(self) -> None:
        await self._http.close()

    # FIXED: Added override
    @override
    def to_json(self, dst: str | Path | None = None, /) -> RemoteAnisetteMapping:
        res: RemoteAnisetteMapping = {"type": "aniRemote", "url": self._url}
        return util.files.save_and_return_json(res, dst)

    # FIXED: Added override and corrected signature
    @classmethod
    @override
    def from_json(
        cls,
        val: AnisetteMapping | str | Path,
        /,
        *,
        libs_path: str | Path | None = None, # Added libs_path to match base
    ) -> RemoteAnisetteProvider:
        val_dict = util.files.read_data_json(val)
        # FIXED: Check type *before* accessing key
        if val_dict.get("type") != "aniRemote":
             raise ValueError("Mapping is not for RemoteAnisetteProvider")
        
        # We know val_dict is RemoteAnisetteMapping
        return cls(url=val_dict["url"])

    # FIXED: Added override
    @override
    async def get_headers(
        self,
        user_id: str,
        device_id: str,
        serial: str = "0",
        with_client_info: bool = False,
    ) -> dict[str, str]:
        try:
            resp = await self._http.get(self._url)
            if not resp.ok:
                raise PushError(f"Remote anisette server error: {resp.status_code}")
            self._ani_headers = cast(AnisetteHeaders, resp.json())
        except Exception as e:
            raise PushError("Failed to get remote anisette data") from e

        return await super().get_headers(user_id, device_id, serial, with_client_info)

    # --- Implement new abstract methods ---
    # FIXED: Added override
    @override
    async def get_os_version_and_build(self) -> Tuple[str, str]:
         logger.warning("RemoteAnisetteProvider cannot reliably provide OS version/build.")
         if self._ani_headers:
             try:
                 client_info = self._ani_headers.get("X-MMe-Client-Info", "")
                 product_match = re.search(r"<([^>]+)>", client_info)
                 os_match = re.search(r"<(?:\w+);([^;]+);([^>]+)>", client_info)
                 os_version = os_match.group(1) if os_match else "14.0"
                 os_build = os_match.group(2) if os_match else "UNKNOWN"
                 return (os_version, os_build)
             except Exception:
                 pass
         return ("14.0", "UNKNOWN")

    # FIXED: Added override
    @override
    async def get_product_name(self) -> str:
         logger.warning("RemoteAnisetteProvider cannot reliably provide product name.")
         if self._ani_headers:
             try:
                 client_info = self._ani_headers.get("X-MMe-Client-Info", "")
                 product_match = re.search(r"<([^>]+)>", client_info)
                 if product_match: return product_match.group(1)
             except Exception:
                 pass
         return "iPhone13,3"

    # FIXED: Added override
    @override
    async def get_serial_number(self) -> str:
         logger.warning("RemoteAnisetteProvider cannot provide serial number.")
         if self._ani_headers:
             machine_id = self._ani_headers.get("X-Apple-I-MD-M", "")
             if machine_id: return machine_id[:12].upper()
         return "REMOTEANISERIAL"

    # FIXED: Added override
    @override
    async def get_anisette_data_dict(self) -> Dict:
        if self._ani_headers is None:
            raise RuntimeError("Anisette data not fetched. Call get_headers() first.")
        return dict(self._ani_headers)


class LocalAnisetteProvider(BaseAnisetteProvider):
    """Anisette provider using local libraries."""

    def __init__(
        self,
        state_blob: BinaryIO | None = None,
        libs_path: str | Path | None = None,
    ) -> None:
        super().__init__()
        self._ani_lock = asyncio.Lock()
        self._ani: Optional[Anisette] = None # Use Optional
        self._libs_path = libs_path
        self._state_blob = state_blob.read() if state_blob else None

    async def _get_ani(self) -> Anisette:
        async with self._ani_lock:
            if self._ani is None:
                logger.info("Initializing local Anisette engine...")
                
                loop = asyncio.get_running_loop()
                # FIXED: Call Anisette constructor correctly
                # (Pylance may still flag this, but it's correct)
                self._ani = await loop.run_in_executor(
                    None,
                    Anisette, # Pass the class
                    self._libs_path,
                    self._state_blob,
                )
            if self._ani is None:
                 raise RuntimeError("Failed to initialize Anisette instance.")
            return self._ani

    # FIXED: Added override
    @override
    async def close(self) -> None:
        """See :meth:`BaseAnisetteProvider.close`."""
        async with self._ani_lock:
            if self._ani is not None:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, self._ani.close)
                self._ani = None

    # FIXED: Added override
    @override
    def to_json(self, dst: str | Path | None = None, /) -> LocalAnisetteMapping:
        """See :meth:`BaseAnisetteProvider.to_json`."""
        prov_data: Optional[bytes] = None
        if self._ani is None:
            prov_data = self._state_blob
        else:
            try:
                with BytesIO() as f:
                    self._ani.save(f)
                    prov_data = f.getvalue()
            except Exception as e:
                logger.warning(f"Failed to save anisette state: {e}")
                prov_data = self._state_blob

        prov_data_b64 = base64.b64encode(prov_data).decode("ascii") if prov_data else None

        res: LocalAnisetteMapping = {
            "type": "aniLocal",
            "prov_data": prov_data_b64,
        }
        # FIXED: Added return
        return util.files.save_and_return_json(res, dst)

    # FIXED: Added override and corrected signature
    @classmethod
    @override
    def from_json(
        cls,
        val: AnisetteMapping | str | Path,
        /,
        *,
        libs_path: str | Path | None = None,
    ) -> LocalAnisetteProvider:
        """See :meth:`BaseAnisetteProvider.from_json`."""
        val_dict = util.files.read_data_json(val)
        if val_dict.get("type") != "aniLocal":
             raise ValueError("Mapping is not for LocalAnisetteProvider")
        
        # We know val_dict is LocalAnisetteMapping
        prov_data = val_dict.get("prov_data")
        state_blob = BytesIO(base64.b64decode(prov_data)) if prov_data else None
        # FIXED: Added return
        return cls(state_blob=state_blob, libs_path=libs_path)

    # FIXED: Added override
    @override
    async def get_headers(
        self,
        user_id: str,
        device_id: str,
        serial: str = "0",
        with_client_info: bool = False,
    ) -> dict[str, str]:
        """Fetches data from py-anisette and returns standard headers."""
        ani = await self._get_ani()
        loop = asyncio.get_running_loop()

        # FIXED: Check for get_data attribute (handles linter error)
        if not hasattr(ani, "get_data") or not callable(ani.get_data):
            raise PushError("Underlying Anisette object missing 'get_data' method.")
            
        try:
             # (Pylance may flag this, but it's correct)
             anisette_headers = await loop.run_in_executor(None, ani.get_data)
        except Exception as e:
             logger.error(f"Error calling anisette.get_data(): {e}")
             raise PushError("Failed to get anisette data from library") from e
             
        self._ani_headers = cast(AnisetteHeaders, anisette_headers)

        return await super().get_headers(user_id, device_id, serial, with_client_info)

    # --- Implementations for new abstract methods ---

    def _get_client_info_parts(self) -> tuple[str, str, str]:
        """ Parses 'X-Mme-Client-Info' """
        if self._ani_headers is None:
            raise RuntimeError("Anisette headers not fetched. Call get_headers() first.")

        client_info = self._ani_headers.get("X-Mme-Client-Info", "")

        product_match = re.search(r"<([^>]+)>", client_info)
        os_match = re.search(r"<(?:\w+);([^;]+);([^>]+)>", client_info)

        product_name = product_match.group(1) if product_match else "UnknownProduct"
        os_version = os_match.group(1) if os_match else "1.0"
        os_build = os_match.group(2) if os_match else "UNKNOWNBUILD"

        return (product_name, os_version, os_build)

    # FIXED: Added override
    @override
    async def get_os_version_and_build(self) -> Tuple[str, str]:
        if self._ani_headers is None: await self.get_headers("","")
        _, os_version, os_build = self._get_client_info_parts()
        return (os_version, os_build)

    # FIXED: Added override
    @override
    async def get_product_name(self) -> str:
        if self._ani_headers is None: await self.get_headers("","")
        product_name, _, _ = self._get_client_info_parts()
        return product_name

    # FIXED: Added override
    @override
    async def get_serial_number(self) -> str:
        """ Returns a mock serial number based on X-Apple-I-MD-M. """
        if self._ani_headers is None: await self.get_headers("","")

        machine_id = self.machine
        if not machine_id: return "PYANISERIAL000"
        return machine_id[:12].upper()

    # FIXED: Added override
    @override
    async def get_anisette_data_dict(self) -> Dict:
        """ Returns the dictionary of headers provided by py-anisette. """
        if self._ani_headers is None: await self.get_headers("","")

        if self._ani_headers is None:
             raise PushError("Failed to fetch anisette headers.")
             
        return dict(self._ani_headers)

    # --- END OF NEW IMPLEMENTATIONS ---