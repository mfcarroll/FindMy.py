# findmy/keychain/cloudkit_manager.py
import base64
import logging
import time
import uuid
from typing import Any, Optional, Type, TYPE_CHECKING, TypeVar, cast

from google.protobuf.message import Message

from findmy.errors import PushError, UnhandledProtocolError, InvalidStateError
# *** Import your actual HttpResponse class ***
from findmy.util.http import HttpSession, HttpResponse
from . import cloudkit_pb2 as ckproto

# Type hints to avoid circular import
if TYPE_CHECKING:
    from findmy.reports.account import AsyncAppleAccount
    from findmy.reports.anisette import BaseAnisetteProvider

logger = logging.getLogger(__name__)

T_Res = TypeVar("T_Res", bound=Message)

CUTTLEFISH_CONTAINER_ID = "com.apple.security.keychain"
CUTTLEFISH_BUNDLE_ID = "com.apple.security.cuttlefish"


class CloudKitManager:
    """Handles CloudKit interactions, including Cuttlefish function calls."""

    def __init__(
        self,
        account: "AsyncAppleAccount",
        anisette_provider: "BaseAnisetteProvider",
        http_session: HttpSession,
    ):
        self.account = account
        self.anisette = anisette_provider
        self.http = http_session
        self.user_id: Optional[str] = None
        self.ck_token: Optional[str] = None
        self.ck_token_expiry: float = 0
        logger.debug("CloudKitManager initialized.")

    async def _ensure_initialized(self):
        """Fetches CloudKit User ID and initial token if needed."""
        if self.user_id and self.ck_token and time.time() < self.ck_token_expiry:
            return

        logger.info("Initializing CloudKit container access...")

        adsid = self.account._login_state_data.get("adsid") if self.account._login_state_data else None
        if not adsid:
            raise PushError("Cannot initialize CloudKit, missing ADSID.")

        # Error 1 (False Positive) is here
        mme_token = await self.account._get_mme_token("mmeAuthToken")

        headers = {
            "Accept": "application/json",
            **(await self.anisette.get_headers(self.account._uid, self.account._devid)),
            "X-Apple-ADSID": adsid,
            "X-Apple-Request-UUID": str(uuid.uuid4()).upper(),
            "X-Apple-CLIENT-TIMEZONE": "PDT",
        }

        init_url = f"https://gateway.icloud.com/setup/ws/1/ckAppInit?container={CUTTLEFISH_CONTAINER_ID}"

        try:
            # self.http.post returns your HttpResponse wrapper
            response: HttpResponse = await self.http.post(
                init_url,
                auth=(self.account._username or "", mme_token),
                headers=headers,
            )

            if not response.ok:
                logger.error(f"ckAppInit failed: {response.status_code}")
                # FIX for Error 2: Remove await
                response_text = response.text()
                logger.error(f"Response: {response_text[:500]}")
                raise PushError(f"ckAppInit failed ({response.status_code})")

            # FIX for Error 3: Remove await
            init_data = response.json()
            self.user_id = init_data.get("cloudKitUserId")

            if not self.user_id:
                raise PushError("ckAppInit response missing cloudKitUserId")

            logger.info(f"CloudKit User ID fetched: {self.user_id}")
            await self._refresh_ck_token()
        except Exception as e:
            logger.error(f"Failed CloudKit initialization: {e}")
            raise PushError("CloudKit container init failed") from e

    async def _refresh_ck_token(self):
        """Refreshes the CloudKit Auth Token."""
        if not self.user_id:
            raise PushError("Cannot refresh CK token without User ID.")

        logger.debug("Refreshing CloudKit token...")

        # Error 4 (False Positive) is here
        mme_token = await self.account._get_mme_token("cloudKitToken")

        headers = {
            "Accept": "application/json",
            "X-CloudKit-AuthToken": mme_token,
            "X-CloudKit-UserId": self.user_id,
            "X-CloudKit-ContainerId": CUTTLEFISH_CONTAINER_ID,
            "X-CloudKit-BundleId": CUTTLEFISH_BUNDLE_ID,
            **(await self.anisette.get_headers(self.account._uid, self.account._devid)),
            "X-Apple-Request-UUID": str(uuid.uuid4()).upper(),
        }

        token_url = "https://gateway.icloud.com/ck/v1/token/request"

        try:
            response: HttpResponse = await self.http.post(token_url, headers=headers)

            if not response.ok:
                  logger.error(f"CK Token request failed: {response.status_code}")
                  # FIX for Error 5: Remove await
                  response_text = response.text()
                  logger.error(f"Response: {response_text[:500]}")
                  raise PushError(f"CK Token request failed ({response.status_code})")

            # FIX for Error 6: Remove await
            token_data = response.json()
            self.ck_token = token_data.get("cloudKitAuthToken")

            self.ck_token_expiry = time.time() + token_data.get("expiresInSeconds", 3600) - 300

            if not self.ck_token:
                 raise PushError("CK Token response missing cloudKitAuthToken")

            logger.info("CloudKit token refreshed.")
        except Exception as e:
            logger.error(f"Failed CloudKit token refresh: {e}")
            self.ck_token = None
            self.ck_token_expiry = 0
            raise PushError("CloudKit token refresh failed") from e

    async def invoke_cuttlefish(
        self,
        method: str,
        request_proto: Message,
        response_class: Type[T_Res],
     ) -> T_Res:
        """Invokes a Cuttlefish function via CloudKit."""
        await self._ensure_initialized()
        if not self.ck_token:
            raise PushError("Cannot invoke Cuttlefish without CloudKit token.")

        logger.info(f"Invoking Cuttlefish method: {method}")
        request_bytes = request_proto.SerializeToString()

        operation_uuid = str(uuid.uuid4()).upper()
        # Errors 7-10 (False Positives) are here
        req_op = ckproto.RequestOperation()
        req_op.header.user_token = ""
        req_op.header.application_container = CUTTLEFISH_CONTAINER_ID
        req_op.header.application_bundle = CUTTLEFISH_BUNDLE_ID
        req_op.header.target_database = ckproto.RequestOperation.Header.PRIVATE_DB
        req_op.header.application_container_environment = ckproto.RequestOperation.Header.PRODUCTION
        req_op.request.operation_uuid = operation_uuid
        req_op.request.type = ckproto.Operation.FUNCTION_INVOKE_TYPE
        req_op.function_invoke_request.service = "Cuttlefish"
        req_op.function_invoke_request.name = method
        req_op.function_invoke_request.parameters = request_bytes

        encoded_op = req_op.SerializeToString()

        def encode_uleb128(value: int) -> bytes:
            result = bytearray()
            while True:
                byte = value & 0x7F
                value >>= 7
                if value == 0:
                    result.append(byte)
                    return bytes(result)
                result.append(byte | 0x80)

        delimited_request_body = encode_uleb128(len(encoded_op)) + encoded_op

        http_headers = {
            "Content-Type" : 'application/x-protobuf; desc="https://gateway.icloud.com:443/static/protobuf/CloudDB/CloudDBClient.desc"; messageType=RequestOperation; delimited=true',
            "Accept" : "application/x-protobuf",
            "X-CloudKit-AuthToken" : self.ck_token,
            "X-CloudKit-UserId" : self.user_id,
            "X-CloudKit-ContainerId" : CUTTLEFISH_CONTAINER_ID,
            "X-CloudKit-BundleId" : CUTTLEFISH_BUNDLE_ID,
            "X-CloudKit-DatabaseScope": "Private",
            "x-cloudkit-functionroutinghint" : f"Cuttlefish/{method}",
            **(await self.anisette.get_headers(self.account._uid, self.account._devid)),
            "X-Apple-Request-UUID" : str(uuid.uuid4()).upper(),
        }

        invoke_url = "https://gateway.icloud.com/ckcoderouter/api/client/code/invoke"

        try:
            response: HttpResponse = await self.http.post(
                invoke_url,
                headers=http_headers,
                data=delimited_request_body
            )

            if not response.ok:
                if response.status_code == 401:
                    logger.warning("CloudKit token likely expired, attempting refresh.")
                    await self._refresh_ck_token()

                    http_headers["X-CloudKit-AuthToken"] = self.ck_token
                    response = await self.http.post(invoke_url, headers=http_headers, data=delimited_request_body)
                    if not response.ok:
                        raise PushError(f"Cuttlefish invoke failed ({response.status_code}) after token refresh")
                else:
                    # FIX for Error 11: Remove await
                    response_text = response.text()
                    logger.error(f"Cuttlefish invoke HTTP error: {response.status_code}")
                    logger.error(f"Response: {response_text[:500]}")
                    raise PushError(f"Cuttlefish invoke HTTP error ({response.status_code})")

            # Parse delimited response
            # FIX for Error 12: Access content bytes directly
            # Assumes HttpResponse has a way to get the raw bytes.
            # Using response._content as per http.py
            # Recommend adding a public property like `content` to HttpResponse.
            response_body = response._content

            def decode_uleb128(data: bytes) -> tuple[int, int]:
                result = 0
                shift = 0
                idx = 0
                while True:
                    if idx >= len(data): raise ValueError("Malformed ULEB128")
                    byte = data[idx]
                    idx += 1
                    result |= (byte & 0x7F) << shift
                    if (byte & 0x80) == 0:
                        return result, idx
                    shift += 7

            resp_ops = []
            offset = 0
            while offset < len(response_body):
               length, len_bytes_read = decode_uleb128(response_body[offset:])
               offset += len_bytes_read
               op_data = response_body[offset : offset + length]
               offset += length
               # Error 13 (False Positive) is here
               resp_op = ckproto.ResponseOperation()
               resp_op.ParseFromString(op_data)
               resp_ops.append(resp_op)

            target_resp = next((op for op in resp_ops if op.response.operation_uuid == operation_uuid), None)
            if not target_resp:
                raise UnhandledProtocolError("CloudKit response missing operation UUID match.")

            # Error 14 (False Positive) is here
            if target_resp.result.code != ckproto.ResponseOperation.Result.SUCCESS:
               error_info = target_resp.result.error
               err_code = error_info.client_error.type if error_info.HasField("client_error") else error_info.server_error.type
               err_reason = error_info.reason
               logger.error(f"CloudKit reported error: Code={err_code}, Reason='{err_reason}'")
               raise PushError(f"CloudKit error ({err_code}): {err_reason}")

            func_resp = target_resp.function_invoke_response
            if not func_resp.HasField("serialized_result"):
                raise UnhandledProtocolError("FunctionInvokeResponse missing serialized_result")

            result_bytes = func_resp.serialized_result

            response_proto = response_class()
            response_proto.ParseFromString(result_bytes)
            logger.info(f"Successfully invoked and parsed Cuttlefish:{method}")
            return response_proto

        except Exception as e:
           logger.error(f"Cuttlefish method {method} failed during HTTP/parsing: {e}")
           raise PushError(f"Cuttlefish:{method} failed") from e