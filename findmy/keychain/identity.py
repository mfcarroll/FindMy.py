"""
findmy.keychain.identity
~~~~~~~~~~~~~~~~~~~~~~~~
Create and persist a local identity for Cuttlefish/CloudKit operations.
"""

from __future__ import annotations

import json
import logging
import os
import platform
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

# --- Local imports ------------------------------------------------------------

from findmy.keychain import cloudkit_pb2 as ckproto
from findmy.keychain.helpers.encoded_peer import GeneratedPeer
from findmy.keychain.crypto_util import (
    generate_ec_keypair,
    serialize_private_key,
    load_private_key,
)

logger = logging.getLogger(__name__)

IDENTITY_FILE = "identity.json"


def duration_since_epoch_millis() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp() * 1000)


def _try_set_field(msg: Any, value: Any, *names: str) -> bool:
    """
    Try to set one of the provided field names (or variants) on the protobuf message.
    Returns True if set, False otherwise.
    """
    for name in names:
        if hasattr(msg, name):
            try:
                setattr(msg, name, value)
                return True
            except Exception:
                pass
    return False


# ------------------------------------------------------------------------------
@dataclass
class KeychainUserIdentity:
    """
    Represents a CloudKit keychain identity — the persistent local identity
    used for signing and encryption within the Find My network.
    """

    machine_id: str
    model_id: str
    _signing_key: EllipticCurvePrivateKey
    _encryption_key: EllipticCurvePrivateKey
    _permanent_info: ckproto.PeerPermanentInfo

    # --------------------------------------------------------------------------

    def __init__(self, machine_id: Optional[str] = None, model_id: Optional[str] = None):
        # Generate EC key pairs (P-384)
        signing_key, signing_pub = generate_ec_keypair()
        encryption_key, encryption_pub = generate_ec_keypair()

        self._signing_key = signing_key
        self._encryption_key = encryption_key
        self.machine_id = machine_id or platform.node()
        self.model_id = model_id or platform.machine()

        # Build PeerPermanentInfo protobuf
        self._permanent_info = ckproto.PeerPermanentInfo()

        # Defensive field assignment (handles naming differences)
        _try_set_field(self._permanent_info, 1, "epoch")
        _try_set_field(
            self._permanent_info,
            signing_pub.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            "signingKey",
        )
        _try_set_field(
            self._permanent_info,
            encryption_pub.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            "encryptionKey",
        )
        _try_set_field(self._permanent_info, self.machine_id, "machineId")
        _try_set_field(self._permanent_info, self.model_id, "modelId")
        _try_set_field(
            self._permanent_info,
            int(datetime.now().timestamp()),
            "creationTime",
        )

        logger.debug(
            f"Generated new PeerPermanentInfo for {self.machine_id} "
            f"({self.model_id}), with EC key pairs."
        )

    # --------------------------------------------------------------------------
    @classmethod
    def load_from_disk(cls, filename: str = IDENTITY_FILE):
        """Loads an existing identity from disk."""
        path = Path(filename)
        if not path.exists():
            raise FileNotFoundError(f"Identity file not found: {path}")

        logger.debug(f"Loading identity from {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        instance = cls(machine_id=data["machine_id"], model_id=data["model_id"])
        instance._signing_key = load_private_key(data["signing_key"].encode())
        instance._encryption_key = load_private_key(data["encryption_key"].encode())

        logger.debug("Successfully loaded KeychainUserIdentity from disk.")
        return instance

    # --------------------------------------------------------------------------
    def save_to_disk(self, filename: str = IDENTITY_FILE):
        """Saves this identity to disk in JSON format."""
        path = Path(filename)
        data = {
            "machine_id": self.machine_id,
            "model_id": self.model_id,
            "signing_key": serialize_private_key(self._signing_key).decode(),
            "encryption_key": serialize_private_key(self._encryption_key).decode(),
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        logger.debug(f"Saved identity to {path}")

    # --------------------------------------------------------------------------
    def to_generated_peer(self):
        """Converts this identity to a GeneratedPeer (for cuttlefish/vouching)."""
        return GeneratedPeer.from_identity(self)

    # --------------------------------------------------------------------------
    def __repr__(self) -> str:  # type: ignore[override]
        return f"<KeychainUserIdentity machine_id={self.machine_id!r} model_id={self.model_id!r}>"


def generate_new_identity(machine_id: str, model_id: str) -> KeychainUserIdentity:
    return KeychainUserIdentity(machine_id, model_id)
