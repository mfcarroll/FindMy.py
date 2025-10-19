import struct
import math
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.backends import default_backend

from .constants import P256_OID

def kdf_ctr_hmac(key: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """
    Implements NIST SP 800-108 KDF in Counter Mode with HMAC-SHA256.
    This is a precise port of the kdf_ctr_hmac function in util.rs.
    """
    output = b""
    
    # --- FIX ---
    # Instantiate the hash to get a concrete digest_size int for Pylance
    digest_size = hashes.SHA256().digest_size 
    rounds = math.ceil(length / digest_size)
    # --- END FIX ---
    
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

def _calculate_key_checksum(key: bytes) -> bytes:
    """Calculates the 2-byte checksum as seen in the Rust code."""
    return (sum(key) & 0xFFFF).to_bytes(2, 'big')

def rfc6637_unwrap_key(
    private_key_pem: bytes, 
    wrapped_key_data: bytes, 
    fingerprint: bytes
) -> bytes:
    """
    Ports the `rfc6637_unwrap_key` function from pcs.rs.
    This is complex and decrypts a key wrapped using ECC-based RFC 6637.
    """
    try:
        # 1. Load the private key (assumed to be P-256)
        private_key = serialization.load_pem_private_key(
            private_key_pem, 
            password=None, 
            backend=default_backend()
        )
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
             raise TypeError("Key is not an Elliptic Curve private key")

        # 2. Parse the wrapped_key_data structure
        #    Format from Rust's `Rfc6637WrappedKey`:
        #    - public_bits (u16, big-endian)
        #    - public_key_data (variable)
        #    - wrapped_size (u8)
        #    - wrapped_key (variable)
        
        public_bits = int.from_bytes(wrapped_key_data[0:2], 'big')
        public_len = (public_bits + 7) // 8
        
        public_key_bytes = wrapped_key_data[2 : 2 + public_len]
        wrapped_size = wrapped_key_data[2 + public_len]
        wrapped_key = wrapped_key_data[3 + public_len : 3 + public_len + wrapped_size]

        # 3. Load the ephemeral public key
        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), 
            public_key_bytes
        )

        # 4. Derive shared secret
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)

        # 5. Construct KDF input parameter
        #    Z || 00000001 || OID || "Anonymous Sender    " || FINGERPRINT
        kdf_input = b"".join([
            shared_secret,
            b'\x00\x00\x00\x01',
            P256_OID,
            b"Anonymous Sender    ", # 20 bytes, as per Rust code
            fingerprint
        ])

        # 6. Derive AES key using SHA256
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(kdf_input)
        aes_key_full = digest.finalize()
        
        # We need a 128-bit (16 byte) key for AES key wrap
        aes_key = aes_key_full[:16]

        # 7. Unwrap the key using AES Key Wrap (RFC 3394)
        unwrapped_padded_key = aes_key_unwrap(aes_key, wrapped_key)
        
        # 8. Unpad and verify checksum
        #    Format: 01 || KEY || CHECKSUM (2 bytes)
        if unwrapped_padded_key[0] != 0x01:
            raise ValueError("Invalid unwrapped key padding")
        
        key_len = len(unwrapped_padded_key) - 3 # 1 byte padding, 2 bytes checksum
        key = unwrapped_padded_key[1 : 1 + key_len]
        checksum = unwrapped_padded_key[1 + key_len:]
        
        if _calculate_key_checksum(key) != checksum:
            raise ValueError("Unwrapped key checksum mismatch")

        return key

    except Exception as e:
        print(f"Error in rfc6637_unwrap_key: {e}")
        raise