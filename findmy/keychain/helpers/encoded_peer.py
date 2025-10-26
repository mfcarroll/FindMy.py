# findmy/keychain/helpers/encoded_peer.py
"""
EncodedPeer helpers for vouching / stable-info signing.

This module provides a thin wrapper around key material and signing helpers.
We use ECDSA P-384 with SHA-384 (Prehashed) to match KeychainUserIdentity behavior.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature


@dataclass
class GeneratedPeer:
    """
    GeneratedPeer stores stable_info bytes and a P-384 keypair used to sign it.

    Note: Your repo already has KeychainUserIdentity which creates and stores keys
    for the *application instance* when it's the sponsor/beneficiary. This helper
    is handy if you want a standalone peer object that generates its own keypair.
    """

    stable_info_bytes: bytes
    private_key: ec.EllipticCurvePrivateKey
    public_key_der: bytes

    @classmethod
    def new(
        cls,
        stable_info_bytes: bytes,
        private_key: Optional[ec.EllipticCurvePrivateKey] = None,
    ):
        if private_key is None:
            private_key = ec.generate_private_key(ec.SECP384R1())
        pub_der = private_key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        return cls(
            stable_info_bytes=stable_info_bytes,
            private_key=private_key,
            public_key_der=pub_der,
        )

    def sign_stable_info(self) -> bytes:
        """Sign stable_info_bytes using ECDSA P-384 and SHA384 prehash. Returns DER signature."""
        h = hashes.Hash(hashes.SHA384())
        h.update(self.stable_info_bytes)
        digest = h.finalize()
        sig = self.private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA384())))
        return sig

    def verify_signature(self, signature: bytes) -> bool:
        pub = self.private_key.public_key()
        h = hashes.Hash(hashes.SHA384())
        h.update(self.stable_info_bytes)
        digest = h.finalize()
        try:
            pub.verify(signature, digest, ec.ECDSA(Prehashed(hashes.SHA384())))
            return True
        except InvalidSignature:
            return False

    def stable_info_b64url(self) -> str:
        return (
            base64.urlsafe_b64encode(self.stable_info_bytes)
            .rstrip(b"=")
            .decode("ascii")
        )

    def public_key_raw_uncompressed(self) -> bytes:
        """Return raw uncompressed EC point (0x04 || X || Y) — may be required by some Apple flows."""
        nums = self.private_key.public_key().public_numbers()
        x = nums.x.to_bytes((nums.x.bit_length() + 7) // 8, "big")
        y = nums.y.to_bytes((nums.y.bit_length() + 7) // 8, "big")
        # P-384 coordinates should be 48 bytes
        coord_len = 48
        x = x.rjust(coord_len, b"\x00")
        y = y.rjust(coord_len, b"\x00")
        return b"\x04" + x + y
