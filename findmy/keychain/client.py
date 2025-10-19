# findmy/keychain/client.py

import logging
import base64
from typing import TypedDict, Dict, List, Optional
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
# CHANGED: Added Prehashed import
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed 
from cryptography.hazmat.primitives.serialization import load_der_public_key

# Import from our existing and new modules
from . import cloudkit_pb2 as ckproto
from .identity import KeychainUserIdentity
from findmy.reports.anisette import BaseAnisetteProvider
from findmy.errors import PushError  # CHANGED: Added PushError import

logger = logging.getLogger(__name__)

# --- Ported EncodedPeer class from keychain.rs ---
# This helper class is used to safely parse and verify
# information from other peers in the keychain circle.

class EncodedPeer:
    """A wrapper for CuttlefishPeer protobufs to verify signatures."""
    def __init__(self, peer_proto: ckproto.CuttlefishPeer):
        self.proto = peer_proto
        self._permanent_info: Optional[ckproto.PeerPermanentInfo] = None
        self._stable_info: Optional[ckproto.PeerStableInfo] = None

    def get_permanent_info(self) -> ckproto.PeerPermanentInfo:
        """Verifies and returns the PeerPermanentInfo."""
        if self._permanent_info:
            return self._permanent_info

        if not self.proto.permanent_info.info:
            raise PushError("Peer has no permanent info")

        # Verify hash
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(self.proto.permanent_info.info)
        hasher.update(self.proto.permanent_info.signature)
        info_hash = hasher.finalize()
        # CHANGED: Use urlsafe_b64encode to match identity.py
        id_hash = f"SHA256:{base64.urlsafe_b64encode(info_hash).decode('ascii').rstrip('=')}"


        if id_hash != self.proto.hash:
            raise PushError(f"Peer hash mismatch: expected {self.proto.hash}, got {id_hash}")

        # Verify signature
        info = ckproto.PeerPermanentInfo()
        info.ParseFromString(self.proto.permanent_info.info)
        
        public_key = load_der_public_key(info.signing_key)
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
             raise PushError("Peer signing key is not an EC key")

        data_to_verify = b"TPPB.PeerPermanentInfo" + self.proto.permanent_info.info
        
        # CHANGED: Hash the data *before* verifying, and use Prehashed
        # This matches how the signature is created in identity.py
        hasher = hashes.Hash(hashes.SHA384())
        hasher.update(data_to_verify)
        digest = hasher.finalize()

        try:
            public_key.verify(
                self.proto.permanent_info.signature,
                digest,  # Pass the digest
                ec.ECDSA(Prehashed(hashes.SHA384())) # Specify Prehashed
            )
        except InvalidSignature:
            logger.warning(f"Peer {self.proto.hash} permanent info signature verification failed!")
            raise PushError("Bad signature on permanent info")
        
        self._permanent_info = info
        return self._permanent_info

    def get_stable_info(self) -> ckproto.PeerStableInfo:
        """Verifies and returns the PeerStableInfo."""
        if self._stable_info:
            return self._stable_info
            
        if not self.proto.stable_info.info:
            raise PushError(f"Peer {self.proto.hash} has no stable info")
            
        permanent_info = self.get_permanent_info()
        signing_key = load_der_public_key(permanent_info.signing_key)
        
        data_to_verify = b"TPPB.PeerStableInfo" + self.proto.stable_info.info

        # CHANGED: Hash the data *before* verifying, and use Prehashed
        hasher = hashes.Hash(hashes.SHA384())
        hasher.update(data_to_verify)
        digest = hasher.finalize()

        try:
            signing_key.verify(
                self.proto.stable_info.signature,
                digest, # Pass the digest
                ec.ECDSA(Prehashed(hashes.SHA384())) # Specify Prehashed
            )
        except InvalidSignature:
            logger.warning(f"Peer {self.proto.hash} stable info signature verification failed!")
            raise PushError("Bad signature on stable info")

        stable_info = ckproto.PeerStableInfo()
        stable_info.ParseFromString(self.proto.stable_info.info)
        self._stable_info = stable_info
        return self._stable_info

# --- State Definitions ---
# These will hold the data we sync from CloudKit
# (Mirroring keychain.rs KeychainClientState)

class KeychainClientState(TypedDict):
    """Holds the complete synchronized state of the keychain."""
    dsid: str
    adsid: str
    host: str
    state_token: Optional[str]
    # Map of Peer ID Hash -> EncodedPeer object
    state: Dict[str, EncodedPeer]
    user_identity: Optional[KeychainUserIdentity]
    # TODO: Add current_bottle, keystore, and items as we port them
    # current_bottle: Optional[CurrentBottle]
    # keystore: KeychainKeyStore
    # items: Dict[str, SavedKeychainZone]


class KeychainClient:
    """
    Main client for interacting with iCloud Keychain (Cuttlefish/PCS).
    """

    def __init__(self,
                 initial_state: KeychainClientState,
                 anisette_provider: BaseAnisetteProvider,
                 # We will need these later:
                 # cloudkit_client: CloudKitClient, 
                 # os_config: YourOSConfigEquivalent
                 ):
        self.state = initial_state
        self.anisette: BaseAnisetteProvider = anisette_provider
        # self.config = os_config
        # self.client = cloudkit_client
        logger.info("KeychainClient initialized.")

    async def generate_stable_info(self) -> ckproto.PeerStableInfo:
        """
        Generates a new PeerStableInfo protobuf.
        This ports `generate_stable_info` from keychain.rs
        """
        logger.debug("Generating new PeerStableInfo...")
        
        # 1. Find the maximum clock from all existing peers
        max_clock = 0
        for peer_hash, peer in self.state['state'].items():
            try:
                stable_info = peer.get_stable_info()
                if stable_info.clock > max_clock:
                    max_clock = stable_info.clock
            except Exception as e:
                logger.warning(f"Could not get stable info for peer {peer_hash}: {e}")

        next_stable_clock = max_clock + 1
        logger.debug(f"Determined next stable clock: {next_stable_clock}")

        # 2. Get hardware/OS details from the Anisette provider
        # We assume the anisette provider can supply these values.
        # You may need to add methods like `get_os_version()` etc. to your provider.
        try:
            # These are placeholders. You must replace them with actual calls
            # to your AnisetteProvider to get real device/OS info.
            os_version = await self.anisette.get_os_version() # e.g., "macOS 14.4.1 (23E224)"
            device_name = await self.anisette.get_device_name() # e.g., "My Mac"
            serial_number = await self.anisette.get_serial_number()
        except AttributeError as e:
             logger.error(f"Anisette provider is missing required methods: {e}")
             # Fallback to plausible dummy data, but this is not ideal
             os_version = "macOS 14.4.1 (23E224)"
             device_name = "findmy.py Client"
             serial_number = "VMW00000000000"

        # 3. Create the stable info object
        stable_info = ckproto.PeerStableInfo()
        stable_info.clock = next_stable_clock
        stable_info.frozen_policy_version = 5
        stable_info.frozen_policy_hash = "SHA256:O/ECQlWhvNlLmlDNh2+nal/yekUC87bXpV3k+6kznSo="
        stable_info.os_version = os_version
        stable_info.device_name = device_name
        stable_info.serial_number = serial_number
        stable_info.flexible_policy_version = 20
        stable_info.flexible_policy_hash = "SHA256:OIzjC3WyLGrM8GAd/EyIfVzTJdYmcGoKPFdQeWeRZTY="
        stable_info.user_controllable_view_status = 1 # 1 = Enabled
        stable_info.is_inherited_account = False
        # Other fields (secrets, recovery keys, etc.) are left default/empty for now

        return stable_info

# --- End of findmy/keychain/client.py ---