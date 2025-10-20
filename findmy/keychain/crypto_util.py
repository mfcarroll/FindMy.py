from asyncio.log import logger
import struct
import math
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from . import cloudkit_pb2 as ckproto
from findmy.errors import PushError
from .constants import P256_OID

def kdf_ctr_hmac(key: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """
    Implements NIST SP 800-108 KDF in Counter Mode with HMAC-SHA256.
    This is a precise port of the kdf_ctr_hmac function in util.rs.
    """
    output = b""
    digest_size = hashes.SHA256().digest_size
    rounds = math.ceil(length / digest_size)
    if rounds > 0xFF:
        raise ValueError("Derived key too long")
    for i in range(1, rounds + 1):
        h = HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(i.to_bytes(4, 'big'))
        h.update(label)
        h.update(context)
        h.update(length.to_bytes(4, 'big'))
        output += h.finalize()
    return output[:length]

def kdf_ctr_hmac_sha384(key: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """
    Implements NIST SP 800-108 KDF in Counter Mode with HMAC-SHA384.
    Adapted from kdf_ctr_hmac (SHA256 version).
    """
    output = b""
    # Use SHA384
    digest_size = hashes.SHA384().digest_size
    rounds = math.ceil(length / digest_size)

    if rounds > 0xFF: # Check counter limit (should be ample)
        raise ValueError("Derived key too long for 4-byte counter")

    for i in range(1, rounds + 1):
        # Use SHA384
        h = HMAC(key, hashes.SHA384(), backend=default_backend())
        h.update(i.to_bytes(4, 'big')) # Counter
        h.update(label)                # Label (Fixed Input Data)
        h.update(context)              # Context (Fixed Input Data)
        h.update(length.to_bytes(4, 'big')) # Output Length L (Fixed Input Data)
        output += h.finalize()

    return output[:length]

def _calculate_key_checksum(key: bytes) -> bytes:
    """Calculates the 2-byte checksum as seen in the Rust code."""
    return (sum(key) & 0xFFFF).to_bytes(2, 'big')

def rfc6637_unwrap_key(private_key_pem: bytes, wrapped_key_data: bytes, fingerprint: bytes) -> bytes:
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise TypeError("Provided key is not an EC private key")

        # Parse wrapped key data (PGP format)
        if wrapped_key_data[0] != 0x84 or wrapped_key_data[1] < 0x27: # Basic check
             raise ValueError("Invalid PGP MPI header for wrapped key")
        len_len = (wrapped_key_data[1] - 0x27) # Bytes used for ephemeral key length
        eph_key_len = int.from_bytes(wrapped_key_data[2:2+len_len], 'big')
        eph_key_start = 2 + len_len
        eph_key_data = wrapped_key_data[eph_key_start : eph_key_start + eph_key_len]
        wrapped_key_start = eph_key_start + eph_key_len
        wrapped_key = wrapped_key_data[wrapped_key_start:]

        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), eph_key_data) # Assumes P-256

        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)

        kdf_input = b"".join([
            shared_secret, b'\x00\x00\x00\x01', P256_OID, b"Anonymous Sender    ", fingerprint
        ])

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(kdf_input)
        aes_key_full = digest.finalize()
        aes_key = aes_key_full[:16] # AES-128 key wrap

        unwrapped_padded_key = aes_key_unwrap(aes_key, wrapped_key)

        if unwrapped_padded_key[0] != 0x01:
            raise ValueError("Invalid unwrapped key padding")
        key_len = len(unwrapped_padded_key) - 3
        key = unwrapped_padded_key[1 : 1 + key_len]
        checksum = int.from_bytes(unwrapped_padded_key[1 + key_len:], 'big')
        calculated_checksum = sum(key) % 65536
        if checksum != calculated_checksum:
            raise ValueError("Invalid checksum on unwrapped key")
        return key
    except Exception as e:
        logger.error(f"RFC 6637 key unwrap failed: {e}")
        raise PushError("Failed to unwrap key") from e


def decrypt_ies_secp384r1_sha384_chacha20poly1305(
    recipient_private_key_pem: bytes,
    ephemeral_public_key_der: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> bytes:
    """
    Decrypts data using ECIES with SECP384r1, KDF-CTR-HMAC-SHA384, and ChaCha20Poly1305.
    This mirrors the decryption process for TLK shares in keychain.rs.

    Args:
        recipient_private_key_pem: PEM-encoded SECP384r1 private key of the recipient.
        ephemeral_public_key_der: DER-encoded SECP384r1 public key from the sender.
        ciphertext: The encrypted data.
        tag: The 16-byte Poly1305 authentication tag.

    Returns:
        The decrypted plaintext bytes.

    Raises:
        ValueError: If keys are invalid or decryption fails.
        InvalidTag: If authentication fails.
        PushError: For wrapped cryptographic errors.
    """
    try:
        # 1. Load keys
        recipient_private_key = serialization.load_pem_private_key(
            recipient_private_key_pem, password=None, backend=default_backend()
        )
        if not isinstance(recipient_private_key, ec.EllipticCurvePrivateKey) or \
           not isinstance(recipient_private_key.curve, ec.SECP384R1):
            raise ValueError("Recipient key must be a SECP384r1 private key.")

        ephemeral_public_key = serialization.load_der_public_key(
            ephemeral_public_key_der, backend=default_backend()
        )
        if not isinstance(ephemeral_public_key, ec.EllipticCurvePublicKey) or \
           not isinstance(ephemeral_public_key.curve, ec.SECP384R1):
            raise ValueError("Ephemeral key must be a SECP384r1 public key.")

        # 2. Perform ECDH key exchange
        shared_secret_z = recipient_private_key.exchange(ec.ECDH(), ephemeral_public_key)
        logger.debug(f"ECDH Shared Secret (Z) length: {len(shared_secret_z)}") # Should be 48 bytes for P-384

        # 3. Derive symmetric key using KDF
        # Label matches keychain.rs kdf label for TLK shares
        kdf_label = b"ckks-v1-tlk-share"
        # Context is the ephemeral public key (DER encoded)
        kdf_context = ephemeral_public_key_der
        # ChaCha20Poly1305 requires a 32-byte (256-bit) key
        key_length = 32

        # Note: keychain.rs uses kdf_ctr_hmac with SHA384 for TLK shares.
        derived_key = kdf_ctr_hmac_sha384(shared_secret_z, kdf_label, kdf_context, key_length)

        logger.debug(f"Derived ChaChaPoly key length: {len(derived_key)}")
        if len(derived_key) != key_length:
             raise ValueError("KDF did not produce expected key length.")

        # 4. Decrypt using ChaCha20Poly1305
        chacha = ChaCha20Poly1305(derived_key)
        # Nonce is typically 12 zero bytes in this scheme
        nonce = b'\x00' * 12
        # `decrypt` requires nonce, ciphertext + tag, and optional AAD
        # No AAD is mentioned for the TLK share decryption in keychain.rs
        try:
            plaintext = chacha.decrypt(nonce, ciphertext + tag, associated_data=None)
            logger.debug("ChaCha20Poly1305 decryption successful.")
            return plaintext
        except InvalidTag:
            logger.error("ChaCha20Poly1305 decryption failed: Invalid authentication tag.")
            raise

    except InvalidTag:
         # Re-raise InvalidTag specifically if needed by caller
         raise
    except Exception as e:
        logger.error(f"IES decryption failed: {e}", exc_info=True)
        raise PushError("IES decryption process failed") from e
# --- END IES DECRYPTION FUNCTION ---

# --- ADD Serialized Key to PEM conversion ---
def convert_serialized_key_to_pem(serialized_key: ckproto.CuttlefishSerializedKey) -> bytes:
    """Converts a CuttlefishSerializedKey protobuf to PKCS8 PEM format."""
    # Assuming CuttlefishSerializedKey contains the key data directly
    # in a field like 'key_data' which holds the DER PKCS#8 bytes.
    # Adjust field name based on your cloudkit_pb2.py definition.
    if not serialized_key.HasField("key_data") or not serialized_key.key_data:
        raise ValueError("Serialized key protobuf is missing key_data field.")

    der_bytes = serialized_key.key_data
    try:
        private_key = serialization.load_der_private_key(der_bytes, password=None)
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem_bytes
    except Exception as e:
        logger.error(f"Failed to convert DER to PEM: {e}")
        raise ValueError("Could not parse or convert key data") from e
# --- END CONVERSION FUNCTION ---