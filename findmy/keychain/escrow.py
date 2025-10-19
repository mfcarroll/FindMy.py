import plistlib
import base64
import struct
import uuid
import srp  # For Secure Remote Password
import asyncio
import os
from datetime import datetime
from typing import TypedDict, Optional, Any, cast

import aiohttp
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- Helper Classes and Functions (Ported from Rust) ---


class EscrowCommand:
    GET_CLUB_CERT = "get_club_cert"
    SRP_INIT = "srp_init"
    RECOVER = "recover"


class EscrowRequest(TypedDict, total=False):
    """A dictionary representing the plist sent to the escrow service."""
    blob: str
    blob_digest: Optional[str]
    command: str
    dsid: str
    label: str
    metadata: Optional[str]
    transactionUUID: str
    userActionLabel: str
    version: int
    baseRootCertVersions: list[int]
    trustedRootCertVersions: list[int]
    silentAttempt: bool


def _msg_from_bin(bin_data: bytes, header_len: int, section_count: int) -> tuple[bytes, list[bytes]]:
    """
    Decodes the custom Apple binary message format.
    Ported from `msg_from_bin` in keychain.rs.
    """
    header = bin_data[:header_len]
    offsets_start = header_len + (section_count * 4)

    # Rust uses u32::from_be_bytes, so big-endian (>)
    offsets = struct.unpack_from(f">{section_count}I", bin_data, header_len)

    total_header_size = offsets_start
    sections: list[bytes] = []

    for i in range(section_count):
        start = total_header_size + int(offsets[i])
        # Read the size of the section (BE)
        size = struct.unpack_from(">I", bin_data, start)[0]
        section_data = bin_data[start + 4 : start + 4 + size]
        sections.append(section_data)

    return header, sections


class KeyVaultMessage:
    """
    Builds the custom Apple binary message format.
    Ported from `KeyVaultMessage` in keychain.rs.
    """

    def __init__(self, header: bytes):
        self.header = header
        self.sections: list[bytes] = []

    def section(self, data: bytes, size: int = 0):
        # Section is [size: 4 bytes, BE] + [data] + [padding]
        payload = struct.pack(">I", len(data)) + data
        if size > 0 and len(payload) < size:
            payload += b"\x00" * (size - len(payload))
        self.sections.append(payload)

    def into_payload(self) -> bytes:
        body = b"".join(self.sections)

        offsets: list[int] = []
        current_offset = 0
        for section in self.sections:
            offsets.append(current_offset)
            current_offset += len(section)

        offset_data = struct.pack(f">{len(offsets)}I", *offsets)

        total = self.header + offset_data + body
        total_len = struct.pack(">I", len(total))  # Outer length is *also* BE

        # Match keychain.rs `create_escrow_blob` which prepends total length
        return total_len + total


def _unpad(data: bytes) -> bytes:
    """Removes PKCS#7 padding."""
    padding_len = data[-1]
    if padding_len > len(data):
        raise ValueError("Invalid padding")
    return data[:-padding_len]


# --- Main Client ---


class EscrowClient:
    """
    Manages the Escrow Recovery process to retrieve the MasterKey.

    This class assumes it is given a fully authenticated 'Account' object
    from your existing findmy/reports/account.py.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        anisette: Any,  # Your AnisetteProvider
        dsid: str,
        username: str,
        pet_token: str,
        mme_auth_token: str,
        escrow_host: str,
    ):
        self.session = session
        self.anisette = anisette
        self.dsid = dsid
        self.username = username
        self.pet_token = pet_token  # X-Apple-I-Api-Token
        self.mme_auth_token = mme_auth_token  # X-MobileMe-AuthToken
        self.host = escrow_host  # e.g., "https://p123-escrowproxy.icloud.com"

        # --- FIX: Reverted to correct srp library attributes ---
        # Use the same 2048-bit group as the Rust library
        self.srp_client = srp.Client(
            srp.constants.GROUP_2048, srp.SHA256
        )
        # --- END FIX ---

    async def _invoke_escrow(self, request_dict: EscrowRequest) -> dict:
        """
        Sends a signed request to the escrow proxy service.
        Ported from `invoke_escrow` in keychain.rs.
        """
        # This Pylance warning is safe to ignore.
        url = f"{self.host}/escrowproxy/api/{request_dict['command']}"

        anisette_headers = await self.anisette.get_anisette_headers()

        headers = {
            "User-Agent": "com.apple.sbd/638.100.48",  # From rustpush
            "Accept-Language": "en-US,en;q=0.9",
            "x-apple-i-device-type": "1",
            "Accept": "*/*",
            "X-Apple-I-Locale": "en_US",
            "X-Mme-Client-Info": await self.anisette.get_client_info(),
            "Content-Type": "application/x-apple-plist",
            **anisette_headers,
        }

        # Create basic auth
        auth = aiohttp.BasicAuth(self.username, self.pet_token)

        # Add the X-MobileMe-AuthToken
        headers["X-MobileMe-AuthToken"] = self.mme_auth_token

        request_data_plist = plistlib.dumps(
            request_dict, fmt=plistlib.PlistFormat.FMT_XML
        )

        async with self.session.post(
            url, data=request_data_plist, headers=headers, auth=auth
        ) as response:
            if not response.ok:
                try:
                    error_content = await response.read()
                    error_plist = plistlib.loads(error_content)
                    raise Exception(f"Escrow error: {error_plist}")
                except Exception as e:
                    raise Exception(f"Escrow HTTP error: {response.status}, {e}")

            content = await response.read()
            return plistlib.loads(content)

    async def recover_master_key(self, password: str) -> bytes:
        """
        Performs the full escrow recovery (SRP + decryption) to get the
        PEM-encoded MasterKey.

        Ported from `try_recover_escrow` in keychain.rs.
        """

        # 1. Get Club Certificate (not used, but part of the flow)
        txn_uuid = str(uuid.uuid4()).upper()
        await self._invoke_escrow(
            {
                "baseRootCertVersions": [101, 500, 103, 102],
                "command": EscrowCommand.GET_CLUB_CERT,
                "label": "com.apple.icdp.record",
                "transactionUUID": txn_uuid,
                "trustedRootCertVersions": [101, 500, 103, 102],
                "userActionLabel": "cdpd: unknown activity",
                "version": 1,
            }
        )

        # 2. SRP Init
        a_bytes = os.urandom(32)
        a_pub = self.srp_client.get_public_key(a_bytes)

        srp_init_req: EscrowRequest = {
            "blob": base64.b64encode(a_pub).decode(),
            "command": EscrowCommand.SRP_INIT,
            "label": "com.apple.icdp.record",
            "transactionUUID": txn_uuid,
            "userActionLabel": "com.apple.sbd: escrow recovery",
            "version": 1,
        }

        srp_init_resp = await self._invoke_escrow(srp_init_req)

        resp_blob = base64.b64decode(srp_init_resp["respBlob"])

        # 3. Process SRP Init Response
        # header=24 bytes, 3 sections (id, salt, b_pub)
        header, sections = _msg_from_bin(resp_blob, 24, 3)
        srp_id, salt, b_pub = sections[0], sections[1], sections[2]

        verifier = self.srp_client.process_reply(
            self.dsid.encode(), password.encode(), salt, b_pub, a_bytes
        )

        m_proof = verifier.get_proof()

        # 4. Send SRP Recover Request
        req_id = struct.unpack_from(">16s", header, 8)[0]
        club_type_id = srp_init_resp.get("clubTypeID", 0)

        # Header: unk1 (165), ver (2 or 0), req_id (16 bytes)
        recover_header = (
            struct.pack(">II", 165, 2 if club_type_id == 1 else 0) + req_id
        )

        kv_msg = KeyVaultMessage(recover_header)
        kv_msg.section(srp_id, size=20)
        kv_msg.section(m_proof)

        recover_req: EscrowRequest = {
            "blob": base64.b64encode(kv_msg.into_payload()).decode(),
            "command": EscrowCommand.RECOVER,
            "label": "com.apple.icdp.record",
            "transactionUUID": txn_uuid,
            "userActionLabel": "com.apple.sbd: escrow recovery",
            "version": 1,
        }

        recover_resp = await self._invoke_escrow(recover_req)

        # 5. Process Recover Response (Decrypt outer layer)
        resp_blob = base64.b64decode(recover_resp["respBlob"])
        header_len = 40 if club_type_id == 1 else 24
        header, sections = _msg_from_bin(resp_blob, header_len, 3)

        server_proof, iv, ciphertext = sections[0], sections[1], sections[2]

        verifier.verify_server_proof(server_proof)
        session_key = verifier.get_session_key()

        version = struct.unpack_from(">I", header, 4)[0]

        if version == 2:
            aesgcm = AESGCM(session_key)
            # The ciphertext includes the 16-byte tag at the end
            decrypted_data = aesgcm.decrypt(iv, ciphertext, None)
        elif version == 0:
            decryptor = Cipher(
                algorithms.AES(session_key),
                modes.CBC(iv),
                backend=default_backend(),
            ).decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        else:
            raise NotImplementedError(f"Unknown escrow version {version}")

        # 6. Process Inner Payload (Decrypt inner layer)
        inner_header, inner_sections = _msg_from_bin(decrypted_data, 16, 6)
        inner_header_data = struct.unpack_from(">IIII", inner_header)
        rounds = inner_header_data[2]

        salt = inner_sections[1]
        encrypted_record = inner_sections[3]
        iv = salt[:16]  # IV is first 16 bytes of salt

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,  # AES-128 key
            salt=salt,
            iterations=rounds,
            backend=default_backend(),
        )
        derived_key = kdf.derive(password.encode())

        decryptor = Cipher(
            algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend()
        ).decryptor()

        bottle_plist_data_padded = (
            decryptor.update(encrypted_record) + decryptor.finalize()
        )
        bottle_plist_data = _unpad(bottle_plist_data_padded)

        # 7. Load Bottle and Derive MasterKey
        bottle_data = plistlib.loads(bottle_plist_data)

        entropy = bottle_data["bottledPeerEntropy"]
        if not isinstance(entropy, bytes):
            raise TypeError("Expected 'bottledPeerEntropy' to be bytes")

        # "Escrow Encryption Private Key" from keychain.rs
        hkdf = HKDF(
            algorithm=hashes.SHA384(),
            length=56,  # 56 bytes for P-384 key derivation
            salt=self.dsid.encode(),
            info=b"Escrow Encryption Private Key",
            backend=default_backend(),
        )
        derived_bytes = hkdf.derive(entropy)

        # 8. Reconstruct ECKey from derived bytes
        # This ports the logic from `derive_ec_key` in keychain.rs
        private_val_int = int.from_bytes(derived_bytes, "big")

        curve = ec.SECP384R1()

        # This is a Pylance false positive
        order = curve.order

        # (entropy % (order - 1)) + 1
        private_scalar = (private_val_int % (order - 1)) + 1

        private_key = ec.derive_private_key(private_scalar, curve, default_backend())

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        print("Successfully recovered MasterKey from escrow.")
        return pem