# findmy/keychain/cuttlefish_client.py
import logging
from typing import TYPE_CHECKING, Optional

# Import generated protobufs
from . import cloudkit_pb2 as ckproto
# Import necessary classes
from findmy.errors import PushError

# Type hint for CloudKitManager to avoid circular import
if TYPE_CHECKING:
    from .cloudkit_manager import CloudKitManager

logger = logging.getLogger(__name__)


class CuttlefishClient:
    """Client for interacting with the Cuttlefish CloudKit service."""

    def __init__(self, cloudkit_manager: "CloudKitManager"):
        self.ck = cloudkit_manager
        logger.debug("CuttlefishClient initialized.")

    async def establish(
        self,
        request: ckproto.CuttlefishEstablshRequest, # Typo in plan: Establsh -> Establish
    ) -> ckproto.CuttlefishEstablishResponse:
        """Invokes the 'establish' Cuttlefish function."""
        logger.info("Calling Cuttlefish establish...")
        try:
            # Corrected protobuf class name
            response = await self.ck.invoke_cuttlefish(
                "establish", request, ckproto.CuttlefishEstablishResponse
            )
            return response
        except PushError as e:
            logger.error(f"Cuttlefish establish failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during Cuttlefish establish: {e}")
            raise PushError("Unexpected error in establish") from e

    async def join_with_voucher(
        self,
        request: ckproto.CuttlefishJoinWithVoucherRequest,
    ) -> ckproto.CuttlefishJoinWithVoucherResponse:
        """Invokes the 'joinWithVoucher' Cuttlefish function."""
        logger.info("Calling Cuttlefish joinWithVoucher...")
        try:
            response = await self.ck.invoke_cuttlefish(
                "joinWithVoucher", request, ckproto.CuttlefishJoinWithVoucherResponse
            )
            return response
        except PushError as e:
            logger.error(f"Cuttlefish joinWithVoucher failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during Cuttlefish joinWithVoucher: {e}")
            raise PushError("Unexpected error in joinWithVoucher") from e

    async def update_trust(
        self,
        request: ckproto.CuttlefishUpdateTrustRequest,
    ) -> ckproto.CuttlefishUpdateTrustResponse:
        """Invokes the 'updateTrust' Cuttlefish function."""
        logger.info("Calling Cuttlefish updateTrust...")
        try:
            response = await self.ck.invoke_cuttlefish(
                "updateTrust", request, ckproto.CuttlefishUpdateTrustResponse
            )
            return response
        except PushError as e:
            logger.error(f"Cuttlefish updateTrust failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during Cuttlefish updateTrust: {e}")
            raise PushError("Unexpected error in updateTrust") from e

    async def fetch_changes(
        self,
        request: ckproto.CuttlefishFetchChangesRequest,
    ) -> ckproto.CuttlefishFetchChangesResponse:
        """Invokes the 'fetchChanges' Cuttlefish function."""
        logger.info("Calling Cuttlefish fetchChanges...")
        try:
            response = await self.ck.invoke_cuttlefish(
                "fetchChanges", request, ckproto.CuttlefishFetchChangesResponse
            )
            return response
        except PushError as e:
            logger.error(f"Cuttlefish fetchChanges failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during Cuttlefish fetchChanges: {e}")
            raise PushError("Unexpected error in fetchChanges") from e

    async def fetch_viable_bottle(
        self,
        request: ckproto.CuttlefishFetchViableBottleRequest,
    ) -> ckproto.CuttlefishFetchViableBottleResponse:
        """Invokes the 'fetchViableBottle' Cuttlefish function."""
        logger.info("Calling Cuttlefish fetchViableBottle...")
        try:
            response = await self.ck.invoke_cuttlefish(
                "fetchViableBottle", request, ckproto.CuttlefishFetchViableBottleResponse
            )
            return response
        except PushError as e:
            logger.error(f"Cuttlefish fetchViableBottle failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during Cuttlefish fetchViableBottle: {e}")
            raise PushError("Unexpected error in fetchViableBottle") from e

    async def fetch_recoverable_tlk_shares(
        self,
        request: ckproto.CuttlefishFetchRecoverableTlkSharesRequest,
    ) -> ckproto.CuttlefishFetchRecoverableTlkSharesResponse:
        """Invokes the 'fetchRecoverableTlkShares' Cuttlefish function."""
        logger.info("Calling Cuttlefish fetchRecoverableTlkShares...")
        try:
            response = await self.ck.invoke_cuttlefish(
                "fetchRecoverableTlkShares",
                request,
                ckproto.CuttlefishFetchRecoverableTlkSharesResponse,
            )
            return response
        except PushError as e:
            logger.error(f"Cuttlefish fetchRecoverableTlkShares failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during Cuttlefish fetchRecoverableTlkShares: {e}")
            raise PushError("Unexpected error in fetchRecoverableTlkShares") from e

    async def reset(
        self,
        request: ckproto.CuttlefishResetRequest,
    ) -> ckproto.CuttlefishResetResponse:
        """Invokes the 'reset' Cuttlefish function."""
        logger.warning("Calling Cuttlefish reset (This is usually destructive!)...")
        try:
            response = await self.ck.invoke_cuttlefish(
                "reset", request, ckproto.CuttlefishResetResponse
            )
            logger.warning("Cuttlefish reset completed.")
            return response
        except PushError as e:
            logger.error(f"Cuttlefish reset failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during Cuttlefish reset: {e}")
            raise PushError("Unexpected error in reset") from e