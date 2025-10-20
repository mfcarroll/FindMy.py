# findmy/keychain/client.py

import logging
import base64
import uuid
import time
from typing import TypedDict, Dict, List, Optional, cast
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed 
from cryptography.hazmat.primitives.serialization import load_der_public_key

# Import from our existing and new modules
from . import cloudkit_pb2 as ckproto
from .identity import KeychainUserIdentity
from findmy.reports.anisette import BaseAnisetteProvider
from findmy.errors import PushError
from .cuttlefish_client import CuttlefishClient
from findmy.reports.account import AsyncAppleAccount

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
    
    def get_dynamic_info(self) -> ckproto.PeerDynamicInfo:
        """Verifies and returns the PeerDynamicInfo."""
        # Similar verification logic as get_stable_info
        if not self.proto.dynamic_info.info:
            raise PushError(f"Peer {self.proto.hash} has no dynamic info")

        permanent_info = self.get_permanent_info()
        signing_key = load_der_public_key(permanent_info.signing_key)

        data_to_verify = b"TPPB.PeerDynamicInfo" + self.proto.dynamic_info.info
        hasher = hashes.Hash(hashes.SHA384())
        hasher.update(data_to_verify)
        digest = hasher.finalize()

        try:
            signing_key.verify(
                self.proto.dynamic_info.signature,
                digest,
                ec.ECDSA(Prehashed(hashes.SHA384()))
            )
        except InvalidSignature:
            logger.warning(f"Peer {self.proto.hash} dynamic info signature verification failed!")
            raise PushError("Bad signature on dynamic info")

        dynamic_info = ckproto.PeerDynamicInfo()
        dynamic_info.ParseFromString(self.proto.dynamic_info.info)
        return dynamic_info

    def get_voucher_unchecked(self) -> Optional[tuple[ckproto.Voucher, ckproto.SignedInfo]]:
        """Parses the voucher without verifying the sponsor's signature yet."""
        if not self.proto.voucher.info:
            return None
        voucher = ckproto.Voucher()
        voucher.ParseFromString(self.proto.voucher.info)
        return voucher, self.proto.voucher # Return parsed and signed

    def validate_voucher(self, voucher_signed: ckproto.SignedInfo, sponsor_signing_key: ec.EllipticCurvePublicKey) -> ckproto.Voucher:
        """Verifies the voucher signature using the sponsor's key."""
        data_to_verify = b"TPPB.Voucher" + voucher_signed.info
        hasher = hashes.Hash(hashes.SHA384())
        hasher.update(data_to_verify)
        digest = hasher.finalize()
        try:
            sponsor_signing_key.verify(
                voucher_signed.signature,
                digest,
                ec.ECDSA(Prehashed(hashes.SHA384()))
            )
        except InvalidSignature:
            logger.warning(f"Voucher signature validation failed!")
            raise PushError("Bad signature on voucher")

        voucher = ckproto.Voucher()
        voucher.ParseFromString(voucher_signed.info)
        return voucher

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
                 # --- ADD AsyncAppleAccount for access to CloudKitManager ---
                 account: AsyncAppleAccount,
                 # os_config: YourOSConfigEquivalent # If needed later
                 ):
        self.state = initial_state
        self.anisette = anisette_provider
        # --- Store account reference ---
        self.account = account # Needed to get CloudKitManager
        # self.config = os_config
        # --- Initialize CuttlefishClient ---
        # We need CloudKitManager, access it via account
        # We assume _get_cloudkit_manager() will be called externally
        # before vouching starts, or lazily create it here.
        # For simplicity, let's assume it's created lazily if needed.
        self._cuttlefish_client: Optional[CuttlefishClient] = None

        logger.info("KeychainClient initialized.")

    async def _get_cuttlefish_client(self) -> CuttlefishClient:
        """Gets or creates the CuttlefishClient instance."""
        if self._cuttlefish_client is None:
            # Get CloudKitManager via the account object
            cloudkit_manager = await self.account._get_cloudkit_manager()
            self._cuttlefish_client = CuttlefishClient(cloudkit_manager)
        return self._cuttlefish_client

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

        # Initialize with defaults
        os_version_build: str = "Unknown"
        product_name: str = "Unknown"
        serial_number: str = "Unknown" # Initialize serial_number too

        try:
            os_version_build = await self.anisette.get_os_version_and_build()
            product_name = await self.anisette.get_product_name()
            serial_number = await self.anisette.get_serial_number()
        except AttributeError as e:
             logger.error(f"Anisette provider is missing required methods: {e}")
             # Fallback to plausible dummy data, but this is not ideal
             os_version = "macOS 14.4.1 (23E224)"
             device_name = "findmy.py Client"
             serial_number = "C02FMYNDMYPY" #Use same fallback as anisette.py

        # 3. Create the stable info object
        stable_info = ckproto.PeerStableInfo()
        stable_info.clock = next_stable_clock
        stable_info.frozen_policy_version = 5
        stable_info.frozen_policy_hash = "SHA256:O/ECQlWhvNlLmlDNh2+nal/yekUC87bXpV3k+6kznSo="
        stable_info.os_version = os_version_build
        stable_info.device_name = product_name
        stable_info.serial_number = serial_number
        stable_info.flexible_policy_version = 20
        stable_info.flexible_policy_hash = "SHA256:OIzjC3WyLGrM8GAd/EyIfVzTJdYmcGoKPFdQeWeRZTY="
        stable_info.user_controllable_view_status = 1 # 1 = Enabled
        stable_info.is_inherited_account = False
        # Other fields (secrets, recovery keys, etc.) are left default/empty for now

        return stable_info

    # --- ADD apply_changes method ---
    def apply_changes(self, changes: ckproto.CuttlefishChanges):
        """Applies received CuttlefishChanges to the local state."""
        logger.debug(f"Applying {len(changes.changes)} changes.")
        self.state['state_token'] = changes.sync_token
        for change in changes.changes:
            if change.add.hash: # Check if add field is populated and has hash
                 peer_hash = change.add.hash
                 logger.debug(f"Adding/Updating peer: {peer_hash}")
                 # Create EncodedPeer to handle verification later if needed
                 self.state['state'][peer_hash] = EncodedPeer(change.add)
            # TODO: Handle removals if the 'remove' field exists in proto
            # elif change.remove.hash:
            #    peer_hash = change.remove.hash
            #    logger.debug(f"Removing peer: {peer_hash}")
            #    self.state['state'].pop(peer_hash, None)
        # TODO: Persist state changes externally if needed
        logger.debug(f"State token updated to: {changes.sync_token}")
    # --- END apply_changes ---

    # --- ADD sync_changes method ---
    async def sync_changes(self) -> bool:
        """Fetches and applies changes from Cuttlefish."""
        logger.info("Fetching Cuttlefish changes...")
        cuttlefish = await self._get_cuttlefish_client()
        token = self.state.get('state_token')

        request = ckproto.CuttlefishFetchChangesRequest(sync_token=token)

        try:
            response = await cuttlefish.fetch_changes(request)
            if response.changes.changes: # Check if there are actual changes
                 self.apply_changes(response.changes)
                 return True # Indicate changes were applied
            else:
                 logger.info("No new changes fetched.")
                 # Update token even if no changes, in case it's the first sync
                 self.state['state_token'] = response.changes.sync_token
                 return False # No changes applied
        except PushError as e:
            if "changeTokenExpired" in str(e): # Simple check
                 logger.warning("CloudKit change token expired, performing full sync.")
                 self.state['state_token'] = None
                 self.state['state'] = {} # Clear local state on full reset
                 # Retry fetching all changes
                 request_reset = ckproto.CuttlefishFetchChangesRequest(sync_token=None)
                 response_reset = await cuttlefish.fetch_changes(request_reset)
                 if response_reset.changes.changes:
                      self.apply_changes(response_reset.changes)
                      return True
                 else:
                      logger.info("No changes after full sync.")
                      self.state['state_token'] = response_reset.changes.sync_token
                      return False
            else:
                 logger.error(f"Failed to fetch changes: {e}")
                 raise # Re-raise other errors
    # --- END sync_changes ---

    # --- ADD ensure_user_identity method ---
    async def ensure_user_identity(self) -> KeychainUserIdentity:
        """Gets or creates the KeychainUserIdentity for this client."""
        if self.state.get('user_identity'):
            return cast(KeychainUserIdentity, self.state['user_identity'])

        logger.info("No user identity found, creating a new one.")
        # We need machine_id and model_id - get from anisette
        try:
            # Assuming these exist from previous steps
            config = self.anisette.get_hardware_config_dict()
            machine_id = config['X-Apple-I-MD-M'] # Machine Data (unique-ish)
            # Model ID comes from client info, needs parsing
            client_info = config.get('X-Mme-Client-Info', '<Unknown;iOS 1.0;Unknown>')
            model_id = client_info.split(';')[0].lstrip('<') # Simple parse
        except (AttributeError, KeyError, IndexError) as e:
            logger.error(f"Could not get required anisette data for identity: {e}")
            # Fallback (less ideal)
            machine_id = str(uuid.uuid4())
            model_id = "findmy.py_Client"

        identity = KeychainUserIdentity(machine_id=machine_id, model_id=model_id)
        self.state['user_identity'] = identity
        # TODO: Persist state externally if needed
        return identity
    # --- END ensure_user_identity ---

    # --- ADD fast_forward_trust method ---
    def _fast_forward_trust(self) -> bool:
        """
        Applies trust updates based on fetched peer data.
        Ports `fast_forward_trust` from keychain.rs. Returns True if state changed.
        """
        identity = cast(KeychainUserIdentity, self.state.get('user_identity'))
        if not identity:
            logger.warning("Cannot fast forward trust without user identity.")
            return False

        current_state = identity.current_state # Direct reference to modify
        initial_clock = current_state.clock
        logger.debug(f"Fast-forwarding trust from clock: {initial_clock}")

        peers_with_dynamic_info = []
        for peer in self.state['state'].values():
            try:
                # Use the EncodedPeer method to verify and get dynamic info
                dynamic_info = peer.get_dynamic_info()
                if dynamic_info.clock > current_state.clock:
                    peers_with_dynamic_info.append((peer, dynamic_info))
            except PushError as e:
                logger.warning(f"Skipping peer {peer.proto.hash} due to error: {e}")
            except Exception as e:
                 logger.error(f"Unexpected error getting dynamic info for {peer.proto.hash}: {e}")


        peers_with_dynamic_info.sort(key=lambda item: item[1].clock)

        modified = False
        for peer, trust_update in peers_with_dynamic_info:
            peer_hash = peer.proto.hash
            logger.debug(f"Considering update {trust_update.clock} from {peer_hash}")

            # Check if we currently trust the peer providing the update
            if peer_hash not in current_state.includeds:
                has_valid_voucher = False
                try:
                    voucher_data = peer.get_voucher_unchecked()
                    if voucher_data:
                        voucher, voucher_signed = voucher_data
                        sponsor_hash = voucher.sponsor
                        beneficiary_hash = voucher.beneficiary

                        if sponsor_hash in current_state.includeds and \
                           beneficiary_hash == peer_hash and \
                           beneficiary_hash not in current_state.excludeds:

                            sponsor_peer = self.state['state'].get(sponsor_hash)
                            if sponsor_peer:
                                sponsor_perm_info = sponsor_peer.get_permanent_info()
                                sponsor_signing_key = load_der_public_key(sponsor_perm_info.signing_key)
                                # Validate signature using sponsor's key
                                peer.validate_voucher(voucher_signed, cast(ec.EllipticCurvePublicKey, sponsor_signing_key))
                                has_valid_voucher = True
                                logger.info(f"Trusting peer {peer_hash} via valid voucher from {sponsor_hash}")
                        else:
                             logger.debug(f"Voucher check failed for {peer_hash}: sponsor trusted={sponsor_hash in current_state.includeds}, beneficiary matches={beneficiary_hash == peer_hash}, not excluded={beneficiary_hash not in current_state.excludeds}")

                except PushError as e:
                     logger.warning(f"Voucher validation failed for {peer_hash}: {e}")
                except Exception as e:
                     logger.error(f"Unexpected error checking voucher for {peer_hash}: {e}")


                if not has_valid_voucher:
                    logger.warning(f"Ignoring trust update from untrusted/unvouched peer {peer_hash}")
                    continue # Skip update from untrusted peer

            # Apply the update
            logger.info(f"Applying trust update {trust_update.clock} from {peer_hash}")
            for included_hash in trust_update.includeds:
                if included_hash not in current_state.includeds:
                    current_state.includeds.append(included_hash)
                    # If previously excluded, remove from excludes
                    if included_hash in current_state.excludeds:
                         current_state.excludeds.remove(included_hash)
                    logger.debug(f"Added included peer: {included_hash}")
                    modified = True

            for excluded_hash in trust_update.excludeds:
                 if excluded_hash not in current_state.excludeds:
                      current_state.excludeds.append(excluded_hash)
                      # If currently included, remove from includes
                      if excluded_hash in current_state.includeds:
                           current_state.includeds.remove(excluded_hash)
                      logger.debug(f"Added excluded peer: {excluded_hash}")
                      modified = True

            current_state.clock = trust_update.clock # Update clock

        if modified:
             logger.info(f"Trust state fast-forwarded to clock: {current_state.clock}")
             # TODO: Persist state changes externally if needed
        else:
             logger.debug("No trust changes applied during fast-forward.")

        return modified
    # --- END fast_forward_trust ---

    # --- ADD sync_trust method ---
    async def sync_trust(self) -> bool:
        """Fetches changes and updates local trust state. Returns True if trust changed."""
        logger.info("Syncing trust state...")
        await self.sync_changes()
        updated = self._fast_forward_trust()
        if updated:
             # If trust changed, push our updated dynamic info
             identity = cast(KeychainUserIdentity, self.state.get('user_identity'))
             if identity and identity.identifier in identity.current_state.includeds: # Check if we are in the circle
                  logger.info("Pushing updated dynamic info after trust sync.")
                  cuttlefish = await self._get_cuttlefish_client()
                  request = ckproto.CuttlefishUpdateTrustRequest(
                       restore_point=self.state.get('state_token'),
                       peer_id=identity.identifier,
                       dynamic_info=identity.sign_dynamic_info()
                  )
                  try:
                       response = await cuttlefish.update_trust(request)
                       if response.changes.changes: # Check if response has changes
                            self.apply_changes(response.changes)
                  except PushError as e:
                       logger.error(f"Failed to push dynamic info update: {e}")
                       # Don't raise, just log, as sync might still be partially valid
             else:
                  logger.info("Not pushing dynamic info as self is not included in the circle.")
        return updated
    # --- END sync_trust ---

    # --- ADD derive_trust_from_included_peer method ---
    async def _derive_trust_from_included_peer(self, peer_id: str):
        """Copies trust state from a known trusted peer before joining."""
        logger.info(f"Deriving initial trust state from peer: {peer_id}")
        await self.sync_changes() # Ensure we have the latest state
        identity = await self.ensure_user_identity()

        sponsor_peer = self.state['state'].get(peer_id)
        if not sponsor_peer:
             logger.error(f"Sponsor peer {peer_id} not found in state.")
             raise PushError("Sponsor peer not found")

        try:
             sponsor_dynamic_info = sponsor_peer.get_dynamic_info()
             # Set our state to match the sponsor's BEFORE we join
             identity.current_state.includeds[:] = sponsor_dynamic_info.includeds # Use slice assignment
             identity.current_state.excludeds[:] = sponsor_dynamic_info.excludeds # Use slice assignment
             identity.current_state.clock = sponsor_dynamic_info.clock
             logger.info(f"Trust state set to match sponsor's clock: {sponsor_dynamic_info.clock}")
             # TODO: Persist state changes
        except PushError as e:
             logger.error(f"Could not get dynamic info from sponsor {peer_id}: {e}")
             raise PushError("Failed to get sponsor's trust state") from e
    # --- END derive_trust_from_included_peer ---


    # --- ADD join_with_voucher method ---
    async def join_with_voucher(self, voucher_b64: str):
        """
        Joins the keychain circle using a base64 encoded voucher.
        Ports `join_clique` logic for the voucher case from keychain.rs.
        """
        logger.info("Attempting to join keychain circle with voucher...")

        # 1. Decode and parse the voucher
        try:
            voucher_bytes = base64.b64decode(voucher_b64)
            voucher_signed = ckproto.SignedInfo()
            voucher_signed.ParseFromString(voucher_bytes)
            voucher = ckproto.Voucher()
            voucher.ParseFromString(voucher_signed.info)
            sponsor_hash = voucher.sponsor
            beneficiary_hash = voucher.beneficiary # This should be us (or unset if generic)
            logger.info(f"Parsed voucher from sponsor: {sponsor_hash}")
        except Exception as e:
            logger.error(f"Failed to decode/parse voucher: {e}")
            raise PushError("Invalid voucher format") from e

        # 2. Ensure we have our own identity
        identity = await self.ensure_user_identity()
        if beneficiary_hash and beneficiary_hash != identity.identifier:
             logger.error(f"Voucher beneficiary ({beneficiary_hash}) does not match our ID ({identity.identifier})")
             raise PushError("Voucher is for a different peer")

        # 3. Derive trust state from the sponsor BEFORE joining
        await self._derive_trust_from_included_peer(sponsor_hash)

        # 4. Generate Stable Info (Needs to happen after potentially syncing state)
        stable_info = await self.generate_stable_info()
        signed_stable_info = identity.sign_stable_info(stable_info)

        # 5. Update *our* dynamic state: Add self, increment clock
        # We start from the state derived from the sponsor
        if identity.identifier not in identity.current_state.includeds:
            identity.current_state.includeds.append(identity.identifier)
            logger.debug(f"Added self ({identity.identifier}) to includeds.")
        # Increment clock based on the derived state + 1
        identity.current_state.clock += 1
        logger.info(f"Joining with dynamic clock: {identity.current_state.clock}")
        signed_dynamic_info = identity.sign_dynamic_info() # Sign the updated state

        # 6. Construct the CuttlefishPeer message including the voucher
        cuttlefish_peer = identity.to_cuttlefish_peer(signed_stable_info, voucher=voucher_signed)

        # 7. Prepare the Join request
        # Note: join_clique in Rust also handles bottles and TLK shares.
        # We simplify here, assuming no initial bottle/shares needed for vouching.
        request = ckproto.CuttlefishJoinWithVoucherRequest(
            restore_point=self.state.get('state_token'),
            peer=cuttlefish_peer,
            # bottle=my_bottle, # Skipping bottle creation for now
            # keys=viewkeys,    # Skipping view keys for now
            # shares=shares     # Skipping initial shares for now
        )

        # 8. Call Cuttlefish
        cuttlefish = await self._get_cuttlefish_client()
        try:
            logger.info("Sending joinWithVoucher request to CloudKit...")
            response = await cuttlefish.join_with_voucher(request)
            logger.info("Successfully joined the circle!")

            # 9. Apply changes returned by the join operation
            if response.changes.changes: # Check if response has changes
                self.apply_changes(response.changes)

            # 10. Update trust again *after* joining, including pushing our state
            await self.sync_trust()

            # TODO: Fetch initial TLK shares after joining if needed
            # shares = await self.fetch_shares_for(identity)
            # await self.store_keys(shares)

        except PushError as e:
            logger.error(f"Failed to join circle with voucher: {e}")
            # Consider reverting local state changes if join fails?
            raise
    # --- END join_with_voucher ---

# --- End of findmy/keychain/client.py ---