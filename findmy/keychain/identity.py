# findmy/keychain/identity.py

import os
import time
import uuid
import logging
import base64
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature
from pathlib import Path
from typing import cast

# Import the generated protobuf classes
from findmy.keychain import cloudkit_pb2 as ckproto
from google.protobuf.message import Message

logger = logging.getLogger(__name__)


# Helper function to match Rust's duration_since_epoch().as_millis()
def duration_since_epoch_millis() -> int:
    return int(time.time() * 1000)


class KeychainUserIdentity:
    """Represents the cryptographic identity of this application instance."""

    def __init__(self, machine_id: str, model_id: str):
        """Generates a new identity."""
        logger.info("Generating new Keychain User Identity...")
        # SECP384r1 curve, matching Rust's Nid::SECP384R1
        self._signing_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(
            ec.SECP384R1()
        )
        self._encryption_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(
            ec.SECP384R1()
        )
        logger.debug("Generated signing and encryption key pairs (SECP384r1).")

        # ** FIX: Constructor ** (Already done correctly here)
        permanent_info = ckproto.PeerPermanentInfo()
        permanent_info.epoch = 1
        permanent_info.permanent_key = self._signing_key.public_key().public_bytes(  # type: ignore
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        permanent_info.encryption_key = self._encryption_key.public_key().public_bytes(  # type: ignore
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        permanent_info.machine_id = machine_id  # type: ignore
        permanent_info.model_id = model_id  # type: ignore
        permanent_info.creation_time = duration_since_epoch_millis()  # type: ignore

        # Sign the permanent info
        self.info: ckproto.SignedInfo = self._sign_payload(
            permanent_info, b"TPPB.PeerPermanentInfo"
        )

        # Calculate the identifier hash (matches Rust implementation)
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(self.info.info)
        hasher.update(self.info.signature)
        info_hash = hasher.finalize()
        # Use urlsafe_b64encode and remove padding to match Rust's base64_encode behavior
        self.identifier: str = (
            f"SHA256:{base64.urlsafe_b64encode(info_hash).decode('ascii').rstrip('=')}"
        )
        logger.info(f"Generated Identity ID: {self.identifier}")

        # Initialize dynamic state (clock starts at 0)
        # ** FIX: Constructor ** (Already done correctly here)
        self.current_state: ckproto.PeerDynamicInfo = ckproto.PeerDynamicInfo()
        self.current_state.clock = 0
        # `includeds`, `excludeds`, etc. are initially empty lists

    def get_signing_key_private_bytes(self) -> bytes:
        """Returns the private signing key in DER format."""
        return self._signing_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def get_encryption_key_private_bytes(self) -> bytes:
        """Returns the private encryption key in DER format."""
        return self._encryption_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def _sign_payload(self, message: Message, type_prefix: bytes) -> ckproto.SignedInfo:
        """Signs a protobuf message with the identity's signing key."""
        serialized_info = message.SerializeToString()
        data_to_sign = type_prefix + serialized_info

        # Hash the data first, as ECDSA typically signs hashes
        # Rust keychain.rs uses SHA384 for signing payloads
        hasher = hashes.Hash(hashes.SHA384())
        hasher.update(data_to_sign)
        digest = hasher.finalize()

        signature = self._signing_key.sign(
            digest, ec.ECDSA(Prehashed(hashes.SHA384()))  # Sign the hash
        )

        # ** FIX: Constructor ** (Already done correctly here)
        signed_info = ckproto.SignedInfo()
        signed_info.info = serialized_info
        signed_info.signature = signature
        logger.debug(f"Signed payload for type: {type_prefix.decode()}")
        return signed_info

    def sign_stable_info(
        self, stable_info: ckproto.PeerStableInfo
    ) -> ckproto.SignedInfo:
        """Creates a SignedInfo object for PeerStableInfo."""
        return self._sign_payload(stable_info, b"TPPB.PeerStableInfo")

    def sign_dynamic_info(self) -> ckproto.SignedInfo:
        """Creates a SignedInfo object for the current PeerDynamicInfo."""
        return self._sign_payload(self.current_state, b"TPPB.PeerDynamicInfo")

    def to_cuttlefish_peer(
        self,
        stable_info_signed: ckproto.SignedInfo,
        voucher: ckproto.SignedInfo | None = None,
    ) -> ckproto.CuttlefishPeer:
        """Constructs the CuttlefishPeer protobuf message for this identity."""
        # ** FIX: Constructor ** (Already done correctly here)
        peer = ckproto.CuttlefishPeer()
        peer.hash = self.identifier  # type: ignore
        peer.permanent_info.CopyFrom(self.info)  # type: ignore
        peer.stable_info.CopyFrom(stable_info_signed)  # type: ignore
        peer.dynamic_info.CopyFrom(self.sign_dynamic_info())  # type: ignore
        if voucher:
            peer.voucher.CopyFrom(voucher)  # type: ignore
        return peer

    @classmethod
    def load_from_disk(
        cls, path: str | Path = "identity.json"
    ) -> "KeychainUserIdentity":
        """Loads a previously saved identity (keys, IDs, state) from disk."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Identity file not found: {p}")

        data = json.loads(p.read_text())
        identity = cls(data["machine_id"], data["model_id"])

        # Restore private keys
        identity._signing_key = cast(
            ec.EllipticCurvePrivateKey,
            serialization.load_der_private_key(
                base64.b64decode(data["signing_key_der"]), password=None
            ),
        )
        identity._encryption_key = cast(
            ec.EllipticCurvePrivateKey,
            serialization.load_der_private_key(
                base64.b64decode(data["encryption_key_der"]), password=None
            ),
        )

        # Restore derived fields
        identity.identifier = data["identifier"]
        identity.current_state.clock = data.get("clock", 0)
        logger.info(f"Loaded KeychainUserIdentity from {p}")
        return identity

    def save_to_disk(self, path: str | Path = "identity.json") -> None:
        """Saves this identity (keys, IDs, state) to disk as JSON."""
        p = Path(path)
        data = {
            "machine_id": getattr(self.info, "machine_id", ""),
            "model_id": getattr(self.info, "model_id", ""),
            "identifier": self.identifier,
            "signing_key_der": base64.b64encode(
                self.get_signing_key_private_bytes()
            ).decode("ascii"),
            "encryption_key_der": base64.b64encode(
                self.get_encryption_key_private_bytes()
            ).decode("ascii"),
            "clock": getattr(self.current_state, "clock", 0),
        }
        p.write_text(json.dumps(data, indent=2))
        logger.info(f"Saved KeychainUserIdentity to {p}")

    @property
    def account(self):
        """Return the bound AsyncAppleAccount if available."""
        return getattr(self, "_account", None)

    @property
    def anisette(self):
        """Return the anisette provider if available."""
        return getattr(self, "_anisette", None)

    @property
    def http(self):
        """Return the aiohttp session or HTTP client if available."""
        return getattr(self, "_http", None)

    def bind_context(self, account, anisette_provider, http_session):
        self._account = account
        self._anisette = anisette_provider
        self._http = http_session

    # TODO: Implement `vouch_for` if this identity needs to act as a sponsor (unlikely for findmy.py)
    # def vouch_for(self, beneficiary_id: str) -> ckproto.SignedInfo:
    #     voucher = ckproto.Voucher()
    #     voucher.reason = 1 # Typically 1 for standard vouching
    #     voucher.beneficiary = beneficiary_id
    #     voucher.sponsor = self.identifier
    #     return self._sign_payload(voucher, b"TPPB.Voucher")


# --- End of findmy/keychain/identity.py ---
