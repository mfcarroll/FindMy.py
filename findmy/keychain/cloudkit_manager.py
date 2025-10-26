# findmy/keychain/cloudkit_manager.py
import base64
import logging
import time
import uuid
from typing import Any, Optional, Type, TYPE_CHECKING, TypeVar, cast, AsyncGenerator

from google.protobuf.message import Message

from findmy.errors import PushError, UnhandledProtocolError, InvalidStateError
from findmy.util.http import HttpSession, HttpResponse
from findmy.keychain import cloudkit_pb2 as ckproto
from .constants import PCS_ZONE_PROTECTED_STORAGE

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
        
    async def fetch_record_zone_changes(
        self,
        zone_name: str,
        sync_token: Optional[str] = None,
        database_scope: ckproto.RequestOperation.Header.DatabaseScope = ckproto.RequestOperation.Header.PRIVATE_DB,
    ) -> AsyncGenerator[ckproto.RecordZoneChangesResponse, None]:
        """
        Fetches record changes for a specific zone using FetchRecordZoneChangesOperation.
        Yields RecordZoneChangesResponse pages.
        """
        await self._ensure_initialized()
        if not self.ck_token:
            raise PushError("Cannot fetch records without CloudKit token.")

        logger.info(f"Fetching record changes for zone: {zone_name} (Scope: {database_scope.name})")

        more_coming = True
        current_sync_token = sync_token

        while more_coming:
            operation_uuid = str(uuid.uuid4()).upper()

            # 1. Build RequestOperation
            req_op = ckproto.RequestOperation()
            # Set Header (similar to invoke_cuttlefish, adjust scope)
            req_op.header.application_container = CUTTLEFISH_CONTAINER_ID # Assuming same container
            req_op.header.application_bundle = CUTTLEFISH_BUNDLE_ID   # Assuming same bundle
            req_op.header.target_database = database_scope
            req_op.header.application_container_environment = ckproto.RequestOperation.Header.PRODUCTION
            # Header user_token is often empty

            # Set Request Body
            req_op.request.operation_uuid = operation_uuid
            req_op.request.type = ckproto.Operation.RECORD_ZONE_CHANGES_TYPE # Type 307

            # Create and populate RecordZoneChangesRequest
            changes_req = ckproto.RecordZoneChangesRequest()
            # Set Zone Identifier
            changes_req.zone_identifier.value.name = zone_name
            # Set Owner Identifier if needed (typically for non-_PCS private zones)
            if database_scope == ckproto.RequestOperation.Header.PRIVATE_DB and zone_name != PCS_ZONE_PROTECTED_STORAGE:
                 changes_req.zone_identifier.owner_identifier.name = f"_{self.user_id}" # Use fetched CloudKit User ID

            if current_sync_token:
                changes_req.sync_token = current_sync_token
            # Set desired keys if needed (optional optimization)
            # changes_req.desired_keys.extend(["field1", "field2"])
            changes_req.num_results = 100 # Request a reasonable number of results per page

            # Assign to the RequestOperation
            req_op.record_zone_changes_request.CopyFrom(changes_req)

            # 2. Serialize and Delimit
            encoded_op = req_op.SerializeToString()

            def encode_uleb128(value: int) -> bytes: # Simple ULEB128 encoder
                result = bytearray()
                while True:
                    byte = value & 0x7F
                    value >>= 7
                    if value == 0:
                        result.append(byte); return bytes(result)
                    result.append(byte | 0x80)

            delimited_request_body = encode_uleb128(len(encoded_op)) + encoded_op

            # 3. Determine Endpoint and Headers
            # Record operations usually use the /database/1/... endpoint
            db_scope_str = "private" if database_scope == ckproto.RequestOperation.Header.PRIVATE_DB else \
                           "public" if database_scope == ckproto.RequestOperation.Header.PUBLIC_DB else \
                           "shared" # Adjust if other scopes used
            invoke_url = f"https://gateway.icloud.com/database/1/{CUTTLEFISH_CONTAINER_ID}/{db_scope_str}/records/changes"

            http_headers = {
                "Content-Type" : 'application/x-protobuf; desc="https://gateway.icloud.com:443/static/protobuf/CloudDB/CloudDBClient.desc"; messageType=RequestOperation; delimited=true',
                "Accept" : "application/x-protobuf",
                "X-CloudKit-AuthToken" : self.ck_token,
                "X-CloudKit-UserId" : self.user_id,
                "X-CloudKit-ContainerId" : CUTTLEFISH_CONTAINER_ID,
                "X-CloudKit-BundleId" : CUTTLEFISH_BUNDLE_ID,
                "X-CloudKit-DatabaseScope": db_scope_str.capitalize(), # "Private", "Public", etc.
                **(await self.anisette.get_headers(self.account._uid, self.account._devid)),
                "X-Apple-Request-UUID" : operation_uuid, # Use same UUID as operation
            }

            # 4. Send Request and Handle Response/Retry
            try:
                response: HttpResponse = await self.http.post(
                    invoke_url,
                    headers=http_headers,
                    data=delimited_request_body
                )

                if not response.ok:
                    if response.status_code == 401:
                        logger.warning("CloudKit token likely expired fetching changes, attempting refresh.")
                        await self._refresh_ck_token()
                        # Retry the request once after refresh
                        http_headers["X-CloudKit-AuthToken"] = self.ck_token
                        response = await self.http.post(invoke_url, headers=http_headers, data=delimited_request_body)
                        if not response.ok:
                            raise PushError(f"Record fetch failed ({response.status_code}) for zone {zone_name} after token refresh")
                    elif response.status_code == 421: # Change token expired
                         # Let the caller handle this specific error type if needed
                         logger.warning(f"CloudKit reported change token expired for zone {zone_name}. Need full resync.")
                         raise PushError(f"changeTokenExpired:{zone_name}") # Signal specific error
                    else:
                        response_text = response.text() # Sync text()
                        logger.error(f"Record fetch HTTP error: {response.status_code} for zone {zone_name}")
                        logger.error(f"Response: {response_text[:500]}")
                        raise PushError(f"Record fetch HTTP error ({response.status_code}) for zone {zone_name}")

                # 5. Parse Delimited Response
                response_body = response._content # Sync content

                def decode_uleb128(data: bytes) -> tuple[int, int]: # Simple ULEB128 decoder
                    result, shift, idx = 0, 0, 0
                    while True:
                        if idx >= len(data): raise ValueError("Malformed ULEB128")
                        byte = data[idx]; idx += 1
                        result |= (byte & 0x7F) << shift
                        if (byte & 0x80) == 0: return result, idx
                        shift += 7

                resp_ops = []
                offset = 0
                while offset < len(response_body):
                   length, len_bytes_read = decode_uleb128(response_body[offset:])
                   offset += len_bytes_read
                   op_data = response_body[offset : offset + length]
                   offset += length
                   resp_op = ckproto.ResponseOperation()
                   resp_op.ParseFromString(op_data)
                   resp_ops.append(resp_op)

                # 6. Find Matching Response and Extract Data
                target_resp = next((op for op in resp_ops if op.response.operation_uuid == operation_uuid), None)
                if not target_resp:
                    raise UnhandledProtocolError(f"CloudKit response missing operation UUID match for zone {zone_name}.")

                if target_resp.result.code != ckproto.ResponseOperation.Result.SUCCESS:
                    error_info = target_resp.result.error
                    err_code = error_info.client_error.type if error_info.HasField("client_error") else error_info.server_error.type
                    err_reason = error_info.reason
                    logger.error(f"CloudKit reported error fetching changes for zone {zone_name}: Code={err_code}, Reason='{err_reason}'")
                    # Check for specific errors like 'changeTokenExpired' if needed
                    if err_reason == "changeTokenExpired":
                         raise PushError(f"changeTokenExpired:{zone_name}")
                    raise PushError(f"CloudKit error ({err_code}) fetching changes for {zone_name}: {err_reason}")

                # Extract the actual changes response
                changes_resp = target_resp.record_zone_changes_response
                if not changes_resp: # Should always be present on success
                     raise UnhandledProtocolError(f"Missing RecordZoneChangesResponse in successful CloudKit response for zone {zone_name}.")

                # 7. Yield the response page
                yield changes_resp

                # 8. Update for next loop iteration
                more_coming = changes_resp.more_coming
                current_sync_token = changes_resp.sync_token
                if more_coming:
                     logger.debug(f"More changes coming for zone {zone_name}, continuing fetch...")
                else:
                     logger.debug(f"Finished fetching changes for zone {zone_name}.")

            except PushError as e:
                 # Re-raise PushErrors to propagate them (like changeTokenExpired)
                 raise
            except Exception as e:
                logger.error(f"Record fetch for zone {zone_name} failed during HTTP/parsing: {e}", exc_info=True)
                raise PushError(f"Record fetch failed for zone {zone_name}") from e