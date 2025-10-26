# findmy/keychain/client.py

import logging
import base64
import uuid
import time
import plistlib
import cbor2
from typing import TypedDict, Dict, List, Optional, cast, Any
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import load_der_public_key
from miscreant.aes.siv import SIV

# Import from our existing and new modules
from . import cloudkit_pb2 as ckproto
from .identity import KeychainUserIdentity
from findmy.reports.anisette import BaseAnisetteProvider
from findmy.errors import PushError, InvalidStateError
from .cuttlefish_client import CuttlefishClient
from findmy.reports.account import AsyncAppleAccount
from findmy.keychain import crypto_util, asn1_defs
from .constants import (
    PCS_ZONE_PROTECTED_STORAGE,
    ZONE_MANATEE,
    ZONE_ENGRAM,
    RECORD_TYPE_SYNCKEY,
    RECORD_TYPE_ITEM,
    RECORD_TYPE_CURRENT_ITEM,
    FINDMY_DEVICE_SECRET_ACCOUNT,
    FINDMY_SERVICE_NAME,
    CUTTLEFISH_ITEM_TYPE,
    CUTTLEFISH_PROTECTION_TAG,
)

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

        # Note: Accessing attributes directly might still show Pylance errors
        # if the .pyi file isn't trusted. Add '# type: ignore' if needed after verification.
        if not self.proto.permanent_info.info:  # type: ignore
            raise PushError("Peer has no permanent info")

        # Verify hash
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(self.proto.permanent_info.info)  # type: ignore
        hasher.update(self.proto.permanent_info.signature)  # type: ignore
        info_hash = hasher.finalize()
        # CHANGED: Use urlsafe_b64encode to match identity.py
        id_hash = (
            f"SHA256:{base64.urlsafe_b64encode(info_hash).decode('ascii').rstrip('=')}"
        )

        if id_hash != self.proto.hash:  # type: ignore
            raise PushError(f"Peer hash mismatch: expected {self.proto.hash}, got {id_hash}")  # type: ignore

        # Verify signature
        info = ckproto.PeerPermanentInfo()
        info.ParseFromString(self.proto.permanent_info.info)  # type: ignore

        public_key = load_der_public_key(info.signing_key)  # type: ignore
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise PushError("Peer signing key is not an EC key")

        data_to_verify = b"TPPB.PeerPermanentInfo" + self.proto.permanent_info.info  # type: ignore

        # CHANGED: Hash the data *before* verifying, and use Prehashed
        # This matches how the signature is created in identity.py
        hasher = hashes.Hash(hashes.SHA384())
        hasher.update(data_to_verify)
        digest = hasher.finalize()

        try:
            public_key.verify(  # type: ignore
                self.proto.permanent_info.signature,  # type: ignore
                digest,  # Pass the digest
                ec.ECDSA(Prehashed(hashes.SHA384())),  # type: ignore # Specify Prehashed
            )
        except InvalidSignature:
            logger.warning(f"Peer {self.proto.hash} permanent info signature verification failed!")  # type: ignore
            raise PushError("Bad signature on permanent info")

        self._permanent_info = info
        return self._permanent_info

    def get_stable_info(self) -> ckproto.PeerStableInfo:
        """Verifies and returns the PeerStableInfo."""
        if self._stable_info:
            return self._stable_info

        if not self.proto.stable_info.info:  # type: ignore
            raise PushError(f"Peer {self.proto.hash} has no stable info")  # type: ignore

        permanent_info = self.get_permanent_info()
        signing_key = load_der_public_key(permanent_info.signing_key)  # type: ignore

        data_to_verify = b"TPPB.PeerStableInfo" + self.proto.stable_info.info  # type: ignore

        # CHANGED: Hash the data *before* verifying, and use Prehashed
        hasher = hashes.Hash(hashes.SHA384())
        hasher.update(data_to_verify)
        digest = hasher.finalize()

        try:
            signing_key.verify(  # type: ignore
                self.proto.stable_info.signature,  # type: ignore
                digest,  # Pass the digest
                ec.ECDSA(Prehashed(hashes.SHA384())),  # type: ignore # Specify Prehashed
            )
        except InvalidSignature:
            logger.warning(f"Peer {self.proto.hash} stable info signature verification failed!")  # type: ignore
            raise PushError("Bad signature on stable info")

        stable_info = ckproto.PeerStableInfo()
        stable_info.ParseFromString(self.proto.stable_info.info)  # type: ignore
        self._stable_info = stable_info
        return self._stable_info

    def get_dynamic_info(self) -> ckproto.PeerDynamicInfo:
        """Verifies and returns the PeerDynamicInfo."""
        # Similar verification logic as get_stable_info
        if not self.proto.dynamic_info.info:  # type: ignore
            raise PushError(f"Peer {self.proto.hash} has no dynamic info")  # type: ignore

        permanent_info = self.get_permanent_info()
        signing_key = load_der_public_key(permanent_info.signing_key)  # type: ignore

        data_to_verify = b"TPPB.PeerDynamicInfo" + self.proto.dynamic_info.info  # type: ignore
        hasher = hashes.Hash(hashes.SHA384())
        hasher.update(data_to_verify)
        digest = hasher.finalize()

        try:
            signing_key.verify(  # type: ignore
                self.proto.dynamic_info.signature,  # type: ignore
                digest,
                ec.ECDSA(Prehashed(hashes.SHA384())),  # type: ignore
            )
        except InvalidSignature:
            logger.warning(f"Peer {self.proto.hash} dynamic info signature verification failed!")  # type: ignore
            raise PushError("Bad signature on dynamic info")

        dynamic_info = ckproto.PeerDynamicInfo()
        dynamic_info.ParseFromString(self.proto.dynamic_info.info)  # type: ignore
        return dynamic_info

    def get_voucher_unchecked(
        self,
    ) -> Optional[tuple[ckproto.Voucher, ckproto.SignedInfo]]:
        """Parses the voucher without verifying the sponsor's signature yet."""
        if not self.proto.voucher.info:  # type: ignore
            return None
        voucher = ckproto.Voucher()
        voucher.ParseFromString(self.proto.voucher.info)  # type: ignore
        return voucher, self.proto.voucher  # type: ignore # Return parsed and signed

    def validate_voucher(
        self,
        voucher_signed: ckproto.SignedInfo,
        sponsor_signing_key: ec.EllipticCurvePublicKey,
    ) -> ckproto.Voucher:
        """Verifies the voucher signature using the sponsor's key."""
        data_to_verify = b"TPPB.Voucher" + voucher_signed.info
        hasher = hashes.Hash(hashes.SHA384())
        hasher.update(data_to_verify)
        digest = hasher.finalize()
        try:
            sponsor_signing_key.verify(  # type: ignore
                voucher_signed.signature, digest, ec.ECDSA(Prehashed(hashes.SHA384()))
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
    state: Dict[str, EncodedPeer]
    user_identity: Optional[KeychainUserIdentity]
    keystore: Dict[str, bytes]
    keychain_items: Dict[str, Dict[str, ckproto.Record]]
    sync_tokens: Dict[str, str]


class KeychainClient:
    """
    Main client for interacting with iCloud Keychain (Cuttlefish/PCS).
    """

    def __init__(
        self,
        initial_state: KeychainClientState,
        anisette_provider: BaseAnisetteProvider,
        account: AsyncAppleAccount,
    ):
        self.state = initial_state
        self.anisette = anisette_provider
        self.account = account  # Needed to get CloudKitManager
        self._cuttlefish_client: Optional[CuttlefishClient] = None

        self.state.setdefault("keystore", {})
        self.state.setdefault(
            "keychain_items",
            {
                PCS_ZONE_PROTECTED_STORAGE: {},
                ZONE_MANATEE: {},
                ZONE_ENGRAM: {},
                # Add other zones if needed
            },
        )
        self.state.setdefault("sync_tokens", {})

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
        for peer_hash, peer in self.state["state"].items():
            try:
                stable_info = peer.get_stable_info()
                if stable_info.clock > max_clock:  # type: ignore
                    max_clock = stable_info.clock  # type: ignore
            except Exception as e:
                logger.warning(f"Could not get stable info for peer {peer_hash}: {e}")

        next_stable_clock = max_clock + 1
        logger.debug(f"Determined next stable clock: {next_stable_clock}")

        # Initialize with defaults
        os_version_build: str = "Unknown"
        product_name: str = "Unknown"
        serial_number: str = "Unknown"  # Initialize serial_number too

        try:
            os_version_build = await self.anisette.get_os_version_and_build()
            product_name = await self.anisette.get_product_name()
            serial_number = await self.anisette.get_serial_number()
        except AttributeError as e:
            logger.error(f"Anisette provider is missing required methods: {e}")
            # Fallback to plausible dummy data, but this is not ideal
            os_version_build = "macOS 14.4.1 (23E224)"  # Corrected variable name
            product_name = "findmy.py Client"  # Corrected variable name
            serial_number = "C02FMYNDMYPY"  # Use same fallback as anisette.py

        # 3. Create the stable info object
        # ** FIX: Constructor **
        stable_info = ckproto.PeerStableInfo()
        stable_info.clock = next_stable_clock
        stable_info.frozen_policy_version = 5  # type: ignore
        stable_info.frozen_policy_hash = "SHA256:O/ECQlWhvNlLmlDNh2+nal/yekUC87bXpV3k+6kznSo="  # type: ignore
        stable_info.os_version = os_version_build  # type: ignore
        stable_info.device_name = product_name  # type: ignore
        stable_info.serial_number = serial_number  # type: ignore
        stable_info.flexible_policy_version = 20  # type: ignore
        stable_info.flexible_policy_hash = "SHA256:OIzjC3WyLGrM8GAd/EyIfVzTJdYmcGoKPFdQeWeRZTY="  # type: ignore
        stable_info.user_controllable_view_status = 1  # type: ignore # 1 = Enabled
        stable_info.is_inherited_account = False  # type: ignore
        # Other fields (secrets, recovery keys, etc.) are left default/empty for now

        return stable_info

    # --- ADD apply_changes method ---
    def apply_changes(self, changes: ckproto.CuttlefishChanges):
        """Applies received CuttlefishChanges to the local state."""
        logger.debug(f"Applying {len(changes.changes)} changes.")  # type: ignore
        self.state["state_token"] = changes.sync_token  # type: ignore
        for change in changes.changes:  # type: ignore
            if (
                change.add.hash
            ):  # Check if add field is populated and has hash # type: ignore
                peer_hash = change.add.hash  # type: ignore
                logger.debug(f"Adding/Updating peer: {peer_hash}")
                # Create EncodedPeer to handle verification later if needed
                self.state["state"][peer_hash] = EncodedPeer(change.add)  # type: ignore
            # TODO: Handle removals if the 'remove' field exists in proto
            # elif change.remove.hash:
            #    peer_hash = change.remove.hash
            #    logger.debug(f"Removing peer: {peer_hash}")
            #    self.state['state'].pop(peer_hash, None)
        # TODO: Persist state changes externally if needed
        logger.debug(f"State token updated to: {changes.sync_token}")  # type: ignore

    # --- END apply_changes ---

    # --- ADD sync_changes method ---
    async def sync_changes(self) -> bool:
        """Fetches and applies changes from Cuttlefish."""
        logger.info("Fetching Cuttlefish changes...")
        cuttlefish = await self._get_cuttlefish_client()
        token = self.state.get("state_token")

        # ** FIX: Constructor **
        request = ckproto.CuttlefishFetchChangesRequest()
        if token:
            request.sync_token = token  # type: ignore

        try:
            response = await cuttlefish.fetch_changes(request)
            if (
                response.changes.changes
            ):  # Check if there are actual changes # type: ignore
                self.apply_changes(response.changes)  # type: ignore
                return True  # Indicate changes were applied
            else:
                logger.info("No new changes fetched.")
                # Update token even if no changes, in case it's the first sync
                self.state["state_token"] = response.changes.sync_token  # type: ignore
                return False  # No changes applied
        except PushError as e:
            if "changeTokenExpired" in str(e):  # Simple check
                logger.warning("CloudKit change token expired, performing full sync.")
                self.state["state_token"] = None
                self.state["state"] = {}  # Clear local state on full reset
                # Retry fetching all changes
                # ** FIX: Constructor **
                request_reset = ckproto.CuttlefishFetchChangesRequest()
                # sync_token=None is default

                response_reset = await cuttlefish.fetch_changes(request_reset)
                if response_reset.changes.changes:  # type: ignore
                    self.apply_changes(response_reset.changes)  # type: ignore
                    return True
                else:
                    logger.info("No changes after full sync.")
                    self.state["state_token"] = response_reset.changes.sync_token  # type: ignore
                    return False
            else:
                logger.error(f"Failed to fetch changes: {e}")
                raise  # Re-raise other errors

    # --- END sync_changes ---

    # --- ADD ensure_user_identity method ---
    async def ensure_user_identity(self) -> KeychainUserIdentity:
        """Gets or creates the KeychainUserIdentity for this client."""
        if self.state.get("user_identity"):
            return cast(KeychainUserIdentity, self.state["user_identity"])

        logger.info("No user identity found, creating a new one.")
        # We need machine_id and model_id - get from anisette
        try:
            # Assuming these exist from previous steps
            config = self.anisette.get_hardware_config_dict()
            machine_id = config["X-Apple-I-MD-M"]  # Machine Data (unique-ish)
            # Model ID comes from client info, needs parsing
            client_info = config.get("X-Mme-Client-Info", "<Unknown;iOS 1.0;Unknown>")
            model_id = client_info.split(";")[0].lstrip("<")  # Simple parse
        except (AttributeError, KeyError, IndexError) as e:
            logger.error(f"Could not get required anisette data for identity: {e}")
            # Fallback (less ideal)
            machine_id = str(uuid.uuid4())
            model_id = "findmy.py_Client"

        identity = KeychainUserIdentity(machine_id=machine_id, model_id=model_id)
        self.state["user_identity"] = identity
        # TODO: Persist state externally if needed
        return identity

    # --- END ensure_user_identity ---

    # --- ADD fast_forward_trust method ---
    def _fast_forward_trust(self) -> bool:
        """
        Applies trust updates based on fetched peer data.
        Ports `fast_forward_trust` from keychain.rs. Returns True if state changed.
        """
        identity = cast(KeychainUserIdentity, self.state.get("user_identity"))
        if not identity:
            logger.warning("Cannot fast forward trust without user identity.")
            return False

        current_state = identity.current_state  # Direct reference to modify
        initial_clock = current_state.clock
        logger.debug(f"Fast-forwarding trust from clock: {initial_clock}")

        peers_with_dynamic_info = []
        for peer in self.state["state"].values():
            try:
                # Use the EncodedPeer method to verify and get dynamic info
                dynamic_info = peer.get_dynamic_info()
                if dynamic_info.clock > current_state.clock:  # type: ignore
                    peers_with_dynamic_info.append((peer, dynamic_info))
            except PushError as e:
                logger.warning(f"Skipping peer {peer.proto.hash} due to error: {e}")  # type: ignore
            except Exception as e:
                logger.error(f"Unexpected error getting dynamic info for {peer.proto.hash}: {e}")  # type: ignore

        peers_with_dynamic_info.sort(key=lambda item: item[1].clock)  # type: ignore

        modified = False
        for peer, trust_update in peers_with_dynamic_info:
            peer_hash = peer.proto.hash  # type: ignore
            logger.debug(f"Considering update {trust_update.clock} from {peer_hash}")  # type: ignore

            # Check if we currently trust the peer providing the update
            if peer_hash not in current_state.includeds:  # type: ignore
                has_valid_voucher = False
                try:
                    voucher_data = peer.get_voucher_unchecked()
                    if voucher_data:
                        voucher, voucher_signed = voucher_data
                        sponsor_hash = voucher.sponsor  # type: ignore
                        beneficiary_hash = voucher.beneficiary  # type: ignore

                        if (
                            sponsor_hash in current_state.includeds
                            and beneficiary_hash == peer_hash
                            and beneficiary_hash not in current_state.excludeds
                        ):  # type: ignore

                            sponsor_peer = self.state["state"].get(sponsor_hash)
                            if sponsor_peer:
                                sponsor_perm_info = sponsor_peer.get_permanent_info()
                                sponsor_signing_key = load_der_public_key(sponsor_perm_info.signing_key)  # type: ignore
                                # Validate signature using sponsor's key
                                peer.validate_voucher(
                                    voucher_signed,
                                    cast(
                                        ec.EllipticCurvePublicKey, sponsor_signing_key
                                    ),
                                )
                                has_valid_voucher = True
                                logger.info(
                                    f"Trusting peer {peer_hash} via valid voucher from {sponsor_hash}"
                                )
                        else:
                            logger.debug(f"Voucher check failed for {peer_hash}: sponsor trusted={sponsor_hash in current_state.includeds}, beneficiary matches={beneficiary_hash == peer_hash}, not excluded={beneficiary_hash not in current_state.excludeds}")  # type: ignore

                except PushError as e:
                    logger.warning(f"Voucher validation failed for {peer_hash}: {e}")
                except Exception as e:
                    logger.error(
                        f"Unexpected error checking voucher for {peer_hash}: {e}"
                    )

                if not has_valid_voucher:
                    logger.warning(
                        f"Ignoring trust update from untrusted/unvouched peer {peer_hash}"
                    )
                    continue  # Skip update from untrusted peer

            # Apply the update
            logger.info(f"Applying trust update {trust_update.clock} from {peer_hash}")  # type: ignore
            for included_hash in trust_update.includeds:  # type: ignore
                if included_hash not in current_state.includeds:  # type: ignore
                    current_state.includeds.append(included_hash)  # type: ignore
                    # If previously excluded, remove from excludes
                    if included_hash in current_state.excludeds:  # type: ignore
                        current_state.excludeds.remove(included_hash)  # type: ignore
                    logger.debug(f"Added included peer: {included_hash}")
                    modified = True

            for excluded_hash in trust_update.excludeds:  # type: ignore
                if excluded_hash not in current_state.excludeds:  # type: ignore
                    current_state.excludeds.append(excluded_hash)  # type: ignore
                    # If currently included, remove from includes
                    if excluded_hash in current_state.includeds:  # type: ignore
                        current_state.includeds.remove(excluded_hash)  # type: ignore
                    logger.debug(f"Added excluded peer: {excluded_hash}")
                    modified = True

            current_state.clock = trust_update.clock  # Update clock # type: ignore

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
            identity = cast(KeychainUserIdentity, self.state.get("user_identity"))
            if (
                identity and identity.identifier in identity.current_state.includeds
            ):  # Check if we are in the circle # type: ignore
                logger.info("Pushing updated dynamic info after trust sync.")
                cuttlefish = await self._get_cuttlefish_client()
                # ** FIX: Constructor **
                request = ckproto.CuttlefishUpdateTrustRequest()
                request.restore_point = self.state.get("state_token")  # type: ignore
                request.peer_id = identity.identifier  # type: ignore
                request.dynamic_info.CopyFrom(identity.sign_dynamic_info())  # type: ignore

                try:
                    response = await cuttlefish.update_trust(request)
                    if (
                        response.changes.changes
                    ):  # Check if response has changes # type: ignore
                        self.apply_changes(response.changes)  # type: ignore
                except PushError as e:
                    logger.error(f"Failed to push dynamic info update: {e}")
                    # Don't raise, just log, as sync might still be partially valid
            else:
                logger.info(
                    "Not pushing dynamic info as self is not included in the circle."
                )
        return updated

    # --- END sync_trust ---

    # --- ADD derive_trust_from_included_peer method ---
    async def _derive_trust_from_included_peer(self, peer_id: str):
        """Copies trust state from a known trusted peer before joining."""
        logger.info(f"Deriving initial trust state from peer: {peer_id}")
        await self.sync_changes()  # Ensure we have the latest state
        identity = await self.ensure_user_identity()

        sponsor_peer = self.state["state"].get(peer_id)
        if not sponsor_peer:
            logger.error(f"Sponsor peer {peer_id} not found in state.")
            raise PushError("Sponsor peer not found")

        try:
            sponsor_dynamic_info = sponsor_peer.get_dynamic_info()
            # Set our state to match the sponsor's BEFORE we join
            identity.current_state.includeds[:] = (
                sponsor_dynamic_info.includeds
            )  # Use slice assignment # type: ignore
            identity.current_state.excludeds[:] = (
                sponsor_dynamic_info.excludeds
            )  # Use slice assignment # type: ignore
            identity.current_state.clock = sponsor_dynamic_info.clock  # type: ignore
            logger.info(f"Trust state set to match sponsor's clock: {sponsor_dynamic_info.clock}")  # type: ignore
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
            sponsor_hash = voucher.sponsor  # type: ignore
            beneficiary_hash = (
                voucher.beneficiary
            )  # This should be us (or unset if generic) # type: ignore
            logger.info(f"Parsed voucher from sponsor: {sponsor_hash}")
        except Exception as e:
            logger.error(f"Failed to decode/parse voucher: {e}")
            raise PushError("Invalid voucher format") from e

        # 2. Ensure we have our own identity
        identity = await self.ensure_user_identity()
        if beneficiary_hash and beneficiary_hash != identity.identifier:
            logger.error(
                f"Voucher beneficiary ({beneficiary_hash}) does not match our ID ({identity.identifier})"
            )
            raise PushError("Voucher is for a different peer")

        # 3. Derive trust state from the sponsor BEFORE joining
        await self._derive_trust_from_included_peer(sponsor_hash)

        # 4. Generate Stable Info (Needs to happen after potentially syncing state)
        stable_info = await self.generate_stable_info()
        signed_stable_info = identity.sign_stable_info(stable_info)

        # 5. Update *our* dynamic state: Add self, increment clock
        # We start from the state derived from the sponsor
        if identity.identifier not in identity.current_state.includeds:  # type: ignore
            identity.current_state.includeds.append(identity.identifier)  # type: ignore
            logger.debug(f"Added self ({identity.identifier}) to includeds.")
        # Increment clock based on the derived state + 1
        identity.current_state.clock += 1
        logger.info(f"Joining with dynamic clock: {identity.current_state.clock}")
        signed_dynamic_info = identity.sign_dynamic_info()  # Sign the updated state

        # 6. Construct the CuttlefishPeer message including the voucher
        cuttlefish_peer = identity.to_cuttlefish_peer(
            signed_stable_info, voucher=voucher_signed
        )

        # 7. Prepare the Join request
        # Note: join_clique in Rust also handles bottles and TLK shares.
        # We simplify here, assuming no initial bottle/shares needed for vouching.
        # ** FIX: Constructor **
        request = ckproto.CuttlefishJoinWithVoucherRequest()
        request.restore_point = self.state.get("state_token")  # type: ignore
        request.peer.CopyFrom(cuttlefish_peer)  # type: ignore
        # bottle=my_bottle, # Skipping bottle creation for now
        # keys=viewkeys,    # Skipping view keys for now
        # shares=shares     # Skipping initial shares for now

        # 8. Call Cuttlefish
        cuttlefish = await self._get_cuttlefish_client()
        try:
            logger.info("Sending joinWithVoucher request to CloudKit...")
            response = await cuttlefish.join_with_voucher(request)
            logger.info("Successfully joined the circle!")

            # 9. Apply changes returned by the join operation
            if response.changes.changes:  # Check if response has changes # type: ignore
                self.apply_changes(response.changes)  # type: ignore

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

    def _get_field_value(
        self, record: ckproto.Record, field_name: str
    ) -> Optional[ckproto.Record.Field.Value]:
        """Helper to extract a value from a CloudKit protobuf record's 'fields' list."""
        for (
            field
        ) in record.record_field:  # Note: field name is record_field # type: ignore
            if field.identifier.name == field_name:  # type: ignore
                return field.value  # type: ignore
        return None

    def _get_b64_field(
        self, record: ckproto.Record, field_name: str
    ) -> Optional[bytes]:
        """Helper for b64-encoded string fields (often used for bytes)."""
        val = self._get_field_value(record, field_name)
        # Bytes are often stored in string_value, base64 encoded
        # ** FIX: HasField **
        if val and val.HasField("stringValue"):  # type: ignore
            try:
                return base64.b64decode(val.string_value)  # type: ignore
            except (TypeError, ValueError):
                logger.warning(
                    f"Failed to base64 decode string_value for field '{field_name}'"
                )
                return None
        # Sometimes raw bytes are used
        # ** FIX: HasField **
        elif val and val.HasField("bytesValue"):  # type: ignore
            return val.bytes_value  # type: ignore
        return None

    def _get_string_field(
        self, record: ckproto.Record, field_name: str
    ) -> Optional[str]:
        """Helper for string fields."""
        val = self._get_field_value(record, field_name)
        # ** FIX: HasField **
        if val and val.HasField("stringValue"):  # type: ignore
            return val.string_value  # type: ignore
        return None

    def _get_ref_field(
        self, record: ckproto.Record, field_name: str
    ) -> Optional[ckproto.Record.Reference]:
        """Helper for reference fields."""
        val = self._get_field_value(record, field_name)
        # ** FIX: HasField **
        if val and val.HasField("referenceValue"):  # type: ignore
            return val.reference_value  # type: ignore
        return None

    async def get_decrypted_key(
        self, key_id: str, zone_id: str = PCS_ZONE_PROTECTED_STORAGE
    ) -> bytes:
        """
        Recursively fetches and decrypts a PCS key ('synckey' record),
        returning its PEM-encoded private key. Caches results.
        """
        if key_id in self.state["keystore"]:
            return self.state["keystore"][key_id]

        logger.info(f"Decrypting key: {key_id} in zone {zone_id}...")

        # 1. Fetch the raw 'synckey' record from CloudKit (using CloudKitManager)
        # We need the CloudKitManager for this, not CuttlefishClient
        ck_manager = await self.account._get_cloudkit_manager()  # Use the getter

        # Construct RecordIdentifier
        # ** FIX: Constructor **
        record_identifier = ckproto.RecordIdentifier()
        record_identifier.value.name = key_id  # type: ignore
        record_identifier.zone_identifier.value.name = zone_id  # type: ignore
        # Assuming ownerIdentifier is needed if not _PCS zone, might need adjustment
        if zone_id != PCS_ZONE_PROTECTED_STORAGE:
            record_identifier.zone_identifier.owner_identifier.name = f"_{ck_manager.user_id}"  # type: ignore

        # Build RecordRetrieveRequest (this uses a different endpoint than function invoke)
        # This part requires adding a record retrieve method to CloudKitManager,
        # OR potentially finding keys via Cuttlefish fetchChanges if they sync there.
        # For now, let's *assume* the key records are synced via fetchChanges
        # and are available in self.state['keychain_items'].

        key_record = self.state["keychain_items"].get(zone_id, {}).get(key_id)
        if not key_record:
            # If not found after sync, try fetching directly (Requires CloudKitManager changes)
            logger.warning(
                f"Key record {key_id} not found in synced items for zone {zone_id}. Direct fetch not implemented."
            )
            raise PushError(f"PCS key not found after sync: {key_id}")

        if key_record.type.name != RECORD_TYPE_SYNCKEY:  # type: ignore
            raise PushError(f"Record {key_id} is not a {RECORD_TYPE_SYNCKEY}")

        # 2. Get its wrapped key and parent key reference
        wrapped_key = self._get_b64_field(key_record, "wrappedKey")
        parent_ref = self._get_ref_field(key_record, "parentKeyRef")

        if not wrapped_key or not parent_ref:
            # If a key has no parent, it might be a TLK decrypted via shares
            if key_id in self.state["keystore"]:  # Check if fetched via shares earlier
                logger.debug(
                    f"Key {key_id} has no parent, using pre-loaded key from keystore."
                )
                return self.state["keystore"][key_id]
            else:
                raise PushError(
                    f"Key {key_id} has no parent reference and is not pre-loaded."
                )

        # Ensure parent_ref has necessary fields
        if not parent_ref.record_identifier or not parent_ref.record_identifier.value or not parent_ref.zone_identifier or not parent_ref.zone_identifier.value:  # type: ignore
            raise PushError(f"Parent reference for key {key_id} is incomplete.")

        parent_key_id = parent_ref.record_identifier.value.name  # type: ignore
        parent_zone_id = parent_ref.zone_identifier.value.name  # type: ignore

        # 3. Recursively get the parent's private key (PEM)
        parent_private_key_pem = await self.get_decrypted_key(
            parent_key_id, parent_zone_id
        )

        # 4. Unwrap the key using RFC 6637
        # We need a fingerprint - the Rust code uses "fingerprint", let's assume that for now.
        fingerprint = b"fingerprint"  # Placeholder, might need adjustment
        unwrapped_key_data = crypto_util.rfc6637_unwrap_key(
            parent_private_key_pem, wrapped_key, fingerprint
        )

        # 5. The unwrapped data is an ASN.1-encoded PCSPrivateKey
        pcs_key_struct = asn1_defs.PCSPrivateKey.load(unwrapped_key_data)

        # 6. Extract the actual private key (PKCS#8 DER)
        private_key_info_der = pcs_key_struct["privateKeyInfo"].dump()  # Get DER bytes

        # 7. Convert DER to PEM format for storage/use
        # Use cryptography library for proper PEM encoding
        private_key_obj = serialization.load_der_private_key(
            private_key_info_der, password=None
        )
        key_pem_bytes = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        logger.info(f"Successfully decrypted key: {key_id}")
        self.state["keystore"][key_id] = key_pem_bytes
        # NOTE: External persistence of self.state assumed elsewhere
        return key_pem_bytes

    def _build_aad_v2(self, item_uuid_str: str, record: ckproto.Record) -> bytes:
        """
        Builds the Additional Authenticated Data (AAD) for Cuttlefish v2 (AES-SIV) decryption.
        """
        try:
            item_uuid_bytes = uuid.UUID(item_uuid_str).bytes
            item_type = CUTTLEFISH_ITEM_TYPE  # b"item"
            protection_tag = CUTTLEFISH_PROTECTION_TAG  # b"user"

            # 'data' field is a b64 encoded plist containing metadata
            data_plist_bytes = self._get_b64_field(record, "data")
            if not data_plist_bytes:
                raise ValueError("Item missing 'data' field required for AAD")
            data_plist = plistlib.loads(data_plist_bytes)

            # Extract ctime and mtime (creation/modification timestamps)
            # Protobuf might store these differently than the old code expected
            # Check the actual structure if errors occur. Assume they are ints for now.
            ctime = data_plist.get("ctime", 0)
            mtime = data_plist.get("mtime", 0)
            if not isinstance(ctime, int) or not isinstance(mtime, int):
                logger.warning(
                    f"Unexpected type for ctime/mtime in item {item_uuid_str}. Using 0."
                )
                ctime = mtime = 0

            # AAD components: UUID, Item Type, Protection Tag, ctime, mtime
            # Order matters! Encoded using CBOR.
            aad_components = [item_uuid_bytes, item_type, protection_tag, ctime, mtime]
            return cbor2.dumps(aad_components)
        except Exception as e:
            logger.error(f"Error building AAD for {item_uuid_str}: {e}")
            raise PushError(f"Failed to build AAD for item {item_uuid_str}") from e

    async def decrypt_keychain_item(
        self, item_uuid: str, record: ckproto.Record
    ) -> Optional[Dict[str, Any]]:
        """
        Decrypts a 'item' record (CuttlefishEncItem, encver=2) using AES-SIV.
        """
        logger.info(f"Attempting decryption for keychain item: {item_uuid}")
        try:
            # 1. Parse the 'data' field (b64 plist) to check encver and get encrypted payload
            data_plist_bytes = self._get_b64_field(record, "data")
            if not data_plist_bytes:
                raise ValueError("Item record missing 'data' field")
            data_plist = plistlib.loads(data_plist_bytes)

            encver = data_plist.get("encver")
            if encver != 2:
                logger.warning(
                    f"Skipping item {item_uuid}: Unsupported encryption version {encver} (only v2/AES-SIV supported)."
                )
                return None

            # 2. Get the item's wrapped key and its parent key reference
            wrapped_item_data_key = self._get_b64_field(record, "wrappedKey")
            parent_ref = self._get_ref_field(record, "parentKeyRef")

            if not wrapped_item_data_key or not parent_ref:
                raise ValueError("Item missing wrappedKey or parentKeyRef")
            if not parent_ref.record_identifier or not parent_ref.record_identifier.value or not parent_ref.zone_identifier or not parent_ref.zone_identifier.value:  # type: ignore
                raise ValueError("Item parent reference is incomplete")

            parent_key_id = parent_ref.record_identifier.value.name  # type: ignore
            parent_zone_id = parent_ref.zone_identifier.value.name  # type: ignore

            # 3. Get the parent key (PEM) by recursively decrypting if needed
            unwrapping_key_pem = await self.get_decrypted_key(
                parent_key_id, parent_zone_id
            )

            # 4. Unwrap the item's specific data key using RFC 6637
            # Assume same fingerprint as key unwrapping
            item_data_key = crypto_util.rfc6637_unwrap_key(
                unwrapping_key_pem, wrapped_item_data_key, b"fingerprint"  # Placeholder
            )

            # 5. Get the encrypted payload (v_Data) from the data plist
            encrypted_payload = data_plist.get("v_Data")
            if not isinstance(encrypted_payload, bytes):
                # Plist library decodes <data> tags into bytes
                raise ValueError("Item data plist missing 'v_Data' or not bytes")

            # 6. Build the AAD
            aad = self._build_aad_v2(item_uuid, record)

            # 7. Decrypt using AES-SIV
            siv = SIV(item_data_key)  # Key needs to be 32 or 64 bytes for AES-SIV
            # Ensure item_data_key length is correct (likely 32 bytes for AES-256-SIV)
            if len(item_data_key) not in [32, 64]:
                raise ValueError(f"Invalid key size for AES-SIV: {len(item_data_key)}")

            decrypted_payload = siv.open(
                encrypted_payload, [aad]
            )  # AAD must be a list of bytes
            if decrypted_payload is None:
                raise PushError("AES-SIV decryption failed (authentication error)")

            # 8. The decrypted data is another plist containing the secret
            final_plist = plistlib.loads(decrypted_payload)
            logger.info(f"Successfully decrypted item: {item_uuid}")
            return cast(Dict[str, Any], final_plist)

        except Exception as e:
            logger.error(f"Failed to decrypt item {item_uuid}: {e}")
            # Optionally re-raise specific errors if needed
            return None

    async def fetch_tlk_shares(self) -> List[ckproto.CuttlefishRecoverableTlkShare]:
        """Fetches recoverable TLK shares for the current user identity."""
        identity = await self.ensure_user_identity()
        if not identity:
            raise InvalidStateError("Cannot fetch TLK shares without user identity")

        logger.info(f"Fetching recoverable TLK shares for peer: {identity.identifier}")
        cuttlefish = await self._get_cuttlefish_client()
        # ** FIX: Constructor **
        request = ckproto.CuttlefishFetchRecoverableTlkSharesRequest()
        request.for_peer = identity.identifier  # type: ignore

        try:
            response = await cuttlefish.fetch_recoverable_tlk_shares(request)
            logger.info(f"Fetched {len(response.shares)} TLK shares.")  # type: ignore
            return list(
                response.shares
            )  # Convert repeated field to list # type: ignore
        except PushError as e:
            logger.error(f"Failed to fetch TLK shares: {e}")
            raise PushError("Could not fetch TLK shares") from e

    async def store_tlk_shares(
        self, shares: List[ckproto.CuttlefishRecoverableTlkShare]
    ):
        """Decrypts and stores TLK shares in the keystore."""
        identity = await self.ensure_user_identity()
        if not identity:
            raise InvalidStateError("Cannot store TLK shares without user identity")

        logger.info(f"Processing {len(shares)} fetched TLK shares...")
        keys_added = 0
        for share_container in shares:
            item_uuid = "Unknown"
            try:
                # Basic validation
                # ** FIX: HasField **
                if not share_container.HasField("share") or not share_container.share.HasField("inner"):  # type: ignore
                    logger.warning("Skipping share container missing inner record.")
                    continue
                share_record = share_container.share.inner  # type: ignore
                # ** FIX: Undefined Variable ** (Corrected, but logic below is placeholder)
                # This requires a helper class CuttlefishTlkShare. Assuming it exists.
                # If not, direct parsing of share_record fields is needed.
                # tlk_share = ckproto.CuttlefishTlkShare() # Placeholder object
                # item = tlk_share.from_record(share_record.record_field) # Assuming helper
                # For now, let's parse directly (requires knowing the field names)
                # wrapped_key_b64 = self._get_string_field(share_record, "wrappedKeyField") # Example
                # key_id = self._get_string_field(share_record, "keyIdField") # Example
                logger.warning(
                    "TLK Share parsing/decryption relies on unimplemented CuttlefishTlkShare helper or direct field access."
                )
                continue  # Skip until helper or direct parsing is implemented

                # TODO: Verify share signature using sender's key (requires fetching sender peer)
                # sender_peer = self.state['state'].get(item.sender)
                # if sender_peer:
                #     sender_signing_key = load_der_public_key(sender_peer.get_permanent_info().signing_key)
                #     # Verify item.signature against item.data_for_signing() using sender_signing_key
                # else:
                #     logger.warning(f"Sender peer {item.sender} not found for TLK share verification.")
                #     continue # Skip unverifiable share

                # Decrypt the wrapped key using our identity's encryption key
                # wrapped_key_b64 = item.wrappedkey # Assuming this is b64 string
                # if not wrapped_key_b64:
                #     logger.warning("Skipping TLK share with empty wrapped key.")
                #     continue
                # wrapped_key_plist_bytes = base64.b64decode(wrapped_key_b64)

                # The wrapped key is a KeyedArchive plist containing IESCiphertext
                # key_archive_dict = plistlib.loads(wrapped_key_plist_bytes) # Use loads for bytes
                # We need to manually parse the IESCiphertext structure from the dict
                # This requires knowing the exact keys used in the plist (e.g., 'SFCiphertext')
                # For now, assume a helper function or direct dict access:
                # ciphertext = key_archive_dict.get('SFCiphertext')
                # auth_code = key_archive_dict.get('SFIESAuthenticationCode')
                # eph_key_data = key_archive_dict.get('SFEphemeralSenderPublicKeyExternaRepresentation', {}).get('$objects', [{}])[1].get('NS.data') # Example deep access

                # if not ciphertext or not auth_code or not eph_key_data:
                #     logger.warning(f"Skipping TLK share {item_uuid}: Malformed IESCiphertext plist.")
                #     continue

                # Reconstruct IESCiphertext (or decrypt directly)
                # This needs the IESCiphertext class or equivalent logic from keychain.rs
                # Placeholder: Use a simplified decryption call assuming a helper exists
                # decrypted_key_proto_bytes = decrypt_ies(identity._encryption_key, ...)
                # For now, we cannot proceed without the IES decryption logic.

                # --- TEMPORARY Placeholder ---
                # Assume decryption succeeds and yields the CuttlefishSerializedKey bytes
                # In reality, you need to implement IES decryption here.
                # logger.warning(f"IES decryption for TLK share {item.key_id} not fully implemented.")
                # continue # Skip until IES is done
                # --- End Placeholder ---

                # If decryption worked:
                # decrypted_key_proto = ckproto.CuttlefishSerializedKey()
                # decrypted_key_proto.ParseFromString(decrypted_key_proto_bytes)
                # key_id = decrypted_key_proto.uuid
                # key_pem = convert_serialized_key_to_pem(decrypted_key_proto) # Need conversion helper
                # self.state['keystore'][key_id] = key_pem
                # keys_added += 1

            except Exception as e:
                # ** FIX: HasField **
                item_uuid = share_container.share.inner.record_identifier.value.name if share_container.HasField("share") and share_container.share.HasField("inner") else "Unknown"  # type: ignore
                logger.error(f"Failed to process TLK share {item_uuid}: {e}")

        logger.info(f"Stored {keys_added} decrypted TLKs in keystore.")
        # NOTE: External persistence assumed elsewhere

    async def sync_keychain_zone(self, zone_name: str, full_resync: bool = False):
        """Fetches changes for a specific keychain zone using CloudKitManager."""
        logger.info(
            f"Syncing keychain zone: {zone_name} (Full Resync: {full_resync})..."
        )
        ck_manager = await self.account._get_cloudkit_manager()

        current_sync_token = (
            None if full_resync else self.state.get("sync_tokens", {}).get(zone_name)
        )
        zone_items = self.state["keychain_items"].setdefault(
            zone_name, {}
        )  # Get or create zone dict

        if full_resync:
            logger.info(
                f"Performing full resync for zone {zone_name}, clearing local items."
            )
            zone_items.clear()
            current_sync_token = None  # Ensure token is None for full sync

        more_coming = True  # Assume potentially more initially
        new_sync_token = current_sync_token  # Start with current token
        page_count = 0
        changes_processed = 0

        while more_coming:
            page_count += 1
            logger.debug(f"Fetching page {page_count} for zone {zone_name}...")
            more_coming = False  # Reset for this page fetch
            try:
                # Use the new async generator method
                async for changes_resp in ck_manager.fetch_record_zone_changes(
                    zone_name=zone_name,
                    sync_token=current_sync_token,
                    # database_scope can be specified if not PRIVATE_DB
                ):
                    # Process changes in the response
                    # ** FIX: HasField **
                    if not changes_resp.HasField("changes_by_record_type"):  # type: ignore
                        logger.debug("No changes in this response page.")
                        # Update token even if no changes on this specific page
                        new_sync_token = changes_resp.sync_token  # type: ignore
                        more_coming = (
                            changes_resp.more_coming
                        )  # Check if server indicates more # type: ignore
                        current_sync_token = (
                            new_sync_token  # Use new token for next request
                        )
                        break  # Exit inner loop for this page

                    for (
                        change
                    ) in (
                        changes_resp.changes_by_record_type
                    ):  # Iterate through RecordZoneChanges # type: ignore
                        record = (
                            change.record
                        )  # The actual Record protobuf # type: ignore
                        record_name = record.record_identifier.value.name  # type: ignore

                        if change.type == ckproto.RecordZoneChangesResponse.Change.DELETE:  # type: ignore
                            removed = zone_items.pop(record_name, None)
                            if removed:
                                logger.debug(
                                    f"Deleted record {record_name} from zone {zone_name}."
                                )
                                changes_processed += 1
                        else:  # CREATE or UPDATE
                            zone_items[record_name] = record
                            logger.debug(
                                f"Created/Updated record {record_name} in zone {zone_name}."
                            )
                            changes_processed += 1

                    # Update sync token and pagination flag after processing the page
                    new_sync_token = changes_resp.sync_token  # type: ignore
                    more_coming = changes_resp.more_coming  # type: ignore
                    current_sync_token = (
                        new_sync_token  # Use new token for the next request
                    )

                    if not more_coming:
                        logger.debug(
                            f"No more changes indicated by server for zone {zone_name}."
                        )
                        break  # Exit the async for loop (generator)

                # After processing all pages from the generator (or breaking early)
                break  # Exit the outer while loop if not more_coming

            except PushError as e:
                # Handle specific errors like token expiry
                if "changeTokenExpired" in str(e):
                    logger.warning(
                        f"Change token expired during sync for zone {zone_name}. Retrying with full resync."
                    )
                    # Clear local state and token, then retry the while loop
                    zone_items.clear()
                    current_sync_token = None
                    new_sync_token = None
                    more_coming = True  # Force retry
                    page_count = 0  # Reset page count
                    changes_processed = 0
                    continue  # Retry the while loop
                else:
                    logger.error(f"Sync failed for zone {zone_name}: {e}")
                    raise  # Re-raise other push errors
            except Exception as e:
                logger.error(
                    f"Unexpected error during zone sync {zone_name}: {e}", exc_info=True
                )
                raise PushError(f"Unexpected failure syncing zone {zone_name}") from e

        # Final update of sync token after loop finishes
        if new_sync_token:
            self.state.setdefault("sync_tokens", {})[zone_name] = new_sync_token
            logger.debug(f"Final sync token for zone {zone_name}: {new_sync_token}")
        else:
            # If sync failed or was interrupted, might want to remove the token
            self.state.get("sync_tokens", {}).pop(zone_name, None)
            logger.warning(f"No final sync token obtained for zone {zone_name}.")

        logger.info(
            f"Sync complete for zone {zone_name}. Processed {changes_processed} changes across {page_count} page(s)."
        )
        # NOTE: External persistence of self.state assumed elsewhere

    async def get_device_secrets(self) -> List[Dict[str, Any]]:
        """
        Main method to sync keychain and decrypt FindMy device secrets.
        Assumes the client has successfully joined the circle (e.g., via vouching).
        """
        logger.info("Starting process to fetch Find My device secrets...")
        identity = await self.ensure_user_identity()
        if not identity:
            raise InvalidStateError("Cannot get secrets without user identity")
        if identity.identifier not in identity.current_state.includeds:  # type: ignore
            # We need to be part of the circle first
            raise InvalidStateError(
                "Cannot get secrets: Not currently included in the keychain circle. Join first."
            )

        # 1. Ensure TLKs are available (fetch if needed)
        # Check if any TLKs are already in the keystore
        has_tlks = any(
            k.startswith("TLK:") for k in self.state["keystore"]
        )  # Assuming TLK IDs start with TLK:
        if not has_tlks:
            logger.info("No TLKs found in keystore, fetching shares...")
            try:
                shares = await self.fetch_tlk_shares()
                await self.store_tlk_shares(
                    shares
                )  # This needs IES decryption implemented
                has_tlks = any(k.startswith("TLK:") for k in self.state["keystore"])
                if not has_tlks:
                    logger.warning(
                        "Failed to store TLKs after fetching shares (IES decryption likely missing)."
                    )
                    # Cannot proceed without TLKs
                    raise PushError("Could not obtain TLKs.")
            except PushError as e:
                logger.error(f"Failed to fetch or store TLKs: {e}")
                raise

        # 2. Sync required zones (_PCS for keys, Manatee for items)
        # These need the CloudKitManager record fetching to be implemented
        logger.info("Syncing required keychain zones...")
        try:
            await self.sync_keychain_zone(PCS_ZONE_PROTECTED_STORAGE)
            await self.sync_keychain_zone(ZONE_MANATEE)
        except PushError as e:
            logger.error(f"Zone sync failed: {e}. Cannot proceed.")
            raise

        # 3. Find the FindMy service key record in _PCS
        logger.info(
            f"Searching for FindMy service key ({FINDMY_SERVICE_NAME}) in {PCS_ZONE_PROTECTED_STORAGE} zone..."
        )
        findmy_service_key_id = None
        findmy_service_key_record = None
        pcs_items = self.state["keychain_items"].get(PCS_ZONE_PROTECTED_STORAGE, {})
        for item_id, record in pcs_items.items():
            if record.type.name != RECORD_TYPE_SYNCKEY:  # type: ignore
                continue
            service_name = self._get_string_field(record, "service")
            if service_name == FINDMY_SERVICE_NAME:
                findmy_service_key_id = item_id
                findmy_service_key_record = record
                logger.info(f"Found FindMy service key record: {findmy_service_key_id}")
                break

        if not findmy_service_key_id or not findmy_service_key_record:
            logger.error(
                f"FindMy service key ({FINDMY_SERVICE_NAME}) not found in {PCS_ZONE_PROTECTED_STORAGE} zone after sync."
            )
            raise PushError("FindMy service key not found.")

        # 4. Decrypt the FindMy service key (will use cached/decrypted TLK)
        logger.info(f"Decrypting FindMy service key: {findmy_service_key_id}...")
        try:
            # This call recursively handles decryption back to the TLK
            _ = await self.get_decrypted_key(
                findmy_service_key_id, PCS_ZONE_PROTECTED_STORAGE
            )
            # Result is cached in self.state['keystore']
            logger.info("Successfully decrypted and cached FindMy service key.")
        except Exception as e:
            logger.error(f"Failed to decrypt FindMy service key: {e}")
            raise PushError("Could not decrypt FindMy service key") from e

        # 5. Find and decrypt FindMy secrets in Manatee zone
        logger.info(
            f"Searching for FindMy secrets ({FINDMY_DEVICE_SECRET_ACCOUNT}) in {ZONE_MANATEE} zone..."
        )
        secrets: List[Dict[str, Any]] = []
        manatee_items = self.state["keychain_items"].get(ZONE_MANATEE, {})
        for item_uuid, record in manatee_items.items():
            if record.type.name != RECORD_TYPE_ITEM:  # type: ignore
                continue

            try:
                # Check the 'acct' field inside the 'data' plist
                data_plist_bytes = self._get_b64_field(record, "data")
                if not data_plist_bytes:
                    continue
                data_plist = plistlib.loads(data_plist_bytes)
                account_name = data_plist.get("acct")

                if account_name == FINDMY_DEVICE_SECRET_ACCOUNT:
                    logger.debug(f"Found potential secret item: {item_uuid}")
                    # Check if it's chained to our FindMy service key
                    parent_ref = self._get_ref_field(record, "parentKeyRef")
                    if parent_ref and parent_ref.record_identifier and parent_ref.record_identifier.value and parent_ref.record_identifier.value.name == findmy_service_key_id:  # type: ignore

                        logger.info(f"Decrypting FindMy secret item: {item_uuid}")
                        decrypted_item_plist = await self.decrypt_keychain_item(
                            item_uuid, record
                        )
                        if decrypted_item_plist:
                            # Add identifier for context
                            decrypted_item_plist["_uuid"] = item_uuid
                            secrets.append(decrypted_item_plist)
                        else:
                            logger.warning(f"Decryption failed for item {item_uuid}.")
                    else:
                        parent_id = parent_ref.record_identifier.value.name if parent_ref and parent_ref.record_identifier and parent_ref.record_identifier.value else "None"  # type: ignore
                        logger.debug(
                            f"Skipping item {item_uuid}: Parent key ({parent_id}) is not the FindMy service key ({findmy_service_key_id})."
                        )

            except Exception as e:
                logger.error(f"Error processing Manatee item {item_uuid}: {e}")

        logger.info(
            f"Finished processing. Found {len(secrets)} decrypted FindMy secrets."
        )
        return secrets


# --- End of findmy/keychain/client.py ---
