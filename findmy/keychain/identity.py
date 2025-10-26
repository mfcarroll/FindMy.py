# findmy/keychain/identity.py

import os
import time
import uuid
import logging
import base64  # <-- 1. ADD THIS IMPORT
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature

# Import the generated protobuf classes
from findmy.keychain import cloudkit_pb2 as ckproto
from google.protobuf.message import Message  # <-- 2. ADD THIS IMPORT

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
        self._signing_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP384R1())
        self._encryption_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP384R1())
        logger.debug("Generated signing and encryption key pairs (SECP384r1).")

        permanent_info = ckproto.PeerPermanentInfo()
        permanent_info.epoch = 1
        permanent_info.signing_key = self._signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        permanent_info.encryption_key = self._encryption_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        permanent_info.machine_id = machine_id
        permanent_info.model_id = model_id
        permanent_info.creation_time = duration_since_epoch_millis()

        # Sign the permanent info
        self.info: ckproto.SignedInfo = self._sign_payload(permanent_info, b"TPPB.PeerPermanentInfo")

        # Calculate the identifier hash (matches Rust implementation)
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(self.info.info)
        hasher.update(self.info.signature)
        info_hash = hasher.finalize()
        # Use urlsafe_b64encode and remove padding to match Rust's base64_encode behavior
        self.identifier: str = f"SHA256:{base64.urlsafe_b64encode(info_hash).decode('ascii').rstrip('=')}"
        logger.info(f"Generated Identity ID: {self.identifier}")

        # Initialize dynamic state (clock starts at 0)
        self.current_state: ckproto.PeerDynamicInfo = ckproto.PeerDynamicInfo()
        self.current_state.clock = 0
        # `includeds`, `excludeds`, etc. are initially empty lists

    def get_signing_key_private_bytes(self) -> bytes:
        """Returns the private signing key in DER format."""
        return self._signing_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def get_encryption_key_private_bytes(self) -> bytes:
        """Returns the private encryption key in DER format."""
        return self._encryption_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    # --- Step 3: Implement Signing Method ---
    def _sign_payload(self, message: Message, type_prefix: bytes) -> ckproto.SignedInfo: # <-- 3. FIX TYPE HINT
        """Signs a protobuf message with the identity's signing key."""
        serialized_info = message.SerializeToString()
        data_to_sign = type_prefix + serialized_info

        # Hash the data first, as ECDSA typically signs hashes
        # Rust keychain.rs uses SHA384 for signing payloads
        hasher = hashes.Hash(hashes.SHA384())
        hasher.update(data_to_sign)
        digest = hasher.finalize()

        signature = self._signing_key.sign(
            digest,
            ec.ECDSA(Prehashed(hashes.SHA384())) # Sign the hash
        )

        signed_info = ckproto.SignedInfo()
        signed_info.info = serialized_info
        signed_info.signature = signature
        logger.debug(f"Signed payload for type: {type_prefix.decode()}")
        return signed_info

    def sign_stable_info(self, stable_info: ckproto.PeerStableInfo) -> ckproto.SignedInfo:
        """Creates a SignedInfo object for PeerStableInfo."""
        return self._sign_payload(stable_info, b"TPPB.PeerStableInfo")

    def sign_dynamic_info(self) -> ckproto.SignedInfo:
        """Creates a SignedInfo object for the current PeerDynamicInfo."""
        return self._sign_payload(self.current_state, b"TPPB.PeerDynamicInfo")

    def to_cuttlefish_peer(self, stable_info_signed: ckproto.SignedInfo, voucher: ckproto.SignedInfo | None = None) -> ckproto.CuttlefishPeer:
        """Constructs the CuttlefishPeer protobuf message for this identity."""
        peer = ckproto.CuttlefishPeer()
        peer.hash = self.identifier
        peer.permanent_info.CopyFrom(self.info)
        peer.stable_info.CopyFrom(stable_info_signed)
        peer.dynamic_info.CopyFrom(self.sign_dynamic_info())
        if voucher:
            peer.voucher.CopyFrom(voucher)
        return peer

    # TODO: Implement `vouch_for` if this identity needs to act as a sponsor (unlikely for findmy.py)
    # def vouch_for(self, beneficiary_id: str) -> ckproto.SignedInfo:
    #     voucher = ckproto.Voucher()
    #     voucher.reason = 1 # Typically 1 for standard vouching
    #     voucher.beneficiary = beneficiary_id
    #     voucher.sponsor = self.identifier
    #     return self._sign_payload(voucher, b"TPPB.Voucher")

# --- End of findmy/keychain/identity.py ---