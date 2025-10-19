import requests
import base64
import uuid
import datetime
from typing import Optional, Any
from requests.sessions import Session

# This import is correct, even if Pylance can't find the symbols
from . import cloudkit_pb2 as pb

# This is the container ID for iCloud Keychain
KEYCHAIN_CONTAINER_ID = "com.apple.keychain.cloud"
DEFAULT_DATABASE = "private"
CK_API_URL = f"https://api.apple-cloudkit.com/database/1/{KEYCHAIN_CONTAINER_ID}/{DEFAULT_DATABASE}"

class CloudKitSession:
    """
    A custom CloudKit client that performs user-based authentication,
    porting the logic from the rustpush library.
    
    It assumes it is given an 'anisette_provider' object from the main
    FindMy app that can supply anisette headers and sign data.
    """
    def __init__(self, dsid: str, ck_token: str, session: Session, anisette_provider: Any):
        self.dsid = dsid
        self.ck_token = ck_token
        self.session = session
        self.anisette_provider = anisette_provider
        self.base_url = CK_API_URL

        if not hasattr(self.anisette_provider, "sign_data"):
            raise TypeError("Anisette provider must have a 'sign_data(bytes)' method")
        if not hasattr(self.anisette_provider, "get_anisette_headers"):
            raise TypeError("Anisette provider must have a 'get_anisette_headers()' method")

    def _build_web_auth_token(self) -> str:
        """
        Creates the X-Apple-CloudKit-Request-Key header value.
        Ported from `cloudkit.rs::build_web_auth_token`.
        """
        return base64.b64encode(f"{self.dsid}:{self.ck_token}".encode()).decode()

    # Pylance will error here, but it's correct at runtime
    def _post_operation(self, operation_pb: pb.RequestOperation) -> pb.ResponseOperation:
        """
        Signs and posts a protobuf operation, then parses the response.
        Ported from `cloudkit.rs::CloudKitClient::sign_request`.
        """
        request_uuid = str(uuid.uuid4()).upper()
        
        # 1. Serialize the protobuf request body
        body_bytes = operation_pb.SerializeToString()
        
        # 2. Create the data-to-be-signed
        # Format: "RequestUUID:CurrentISODate:RequestBodyBase64"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds') + "Z"
        body_b64 = base64.b64encode(body_bytes).decode()
        data_to_sign = f"{request_uuid}:{now_iso}:{body_b64}".encode()

        # 3. Sign the data using the device private key (via anisette_provider)
        # This assumes the provider has the device's private signing key.
        signature_b64 = self.anisette_provider.sign_data(data_to_sign)
        
        # 4. Get Anisette headers
        anisette_headers = self.anisette_provider.get_anisette_headers()

        # 5. Build all headers
        headers = {
            "Content-Type": "application/x-protobuf",
            "X-Apple-CloudKit-Request-Key": self._build_web_auth_token(),
            "X-Apple-CloudKit-Request-SignatureV2": signature_b64,
            "X-Apple-CloudKit-Request-ISO8601Date": now_iso,
            "X-Apple-CloudKit-Request-UUID": request_uuid,
            **anisette_headers,
        }

        # 6. Make the POST request
        url = f"{self.base_url}/records/{operation_pb.operation.type}"
        response = None  
        try:
            response = self.session.post(url, data=body_bytes, headers=headers)
            response.raise_for_status() # Raise HTTPError for bad responses
            
            # 7. Parse the protobuf response
            # Pylance will error here, but it's correct at runtime
            response_pb = pb.ResponseOperation()
            response_pb.ParseFromString(response.content)
            return response_pb
            
        except Exception as e:
            print(f"CloudKit request failed: {e}")
            if response is not None:
                print(f"Response: {response.text}")
            else:
                print("No response from server.")
            raise

    def fetch_records(self, record_names: list[str], zone_id: str):
        """
        Fetches specific records by name from a given zone.
        """
        print(f"Fetching {len(record_names)} records from zone {zone_id}...")
        
        # 1. Build Protobuf Request
        # Pylance will error here, but it's correct at runtime
        req = pb.RequestOperation()
        req.operation.type = "lookup"
        
        # Pylance will error here, but it's correct at runtime
        lookup_req = pb.RecordLookupRequest()
        for name in record_names:
            record_id = lookup_req.records.add()
            record_id.record_name = name
            record_id.zone_id.zone_name = zone_id
            
        req.record_lookup_request.CopyFrom(lookup_req)
        
        # 2. Post and get response
        try:
            response_pb = self._post_operation(req)
            # Extract and return the records
            return [record.record for record in response_pb.record_lookup_response.records]
        except Exception as e:
            print(f"Error fetching records: {e}")
            return []

    def fetch_zone_changes(self, zone_id: str, sync_token: Optional[str] = None):
        """
        Fetches changes in a zone since the last sync token.
        
        NOTE: This is a simplified version. The Rust code handles pagination
        via `more_coming`. This implementation just yields the first page.
        A full implementation would need to loop.
        """
        print(f"Fetching changes for zone {zone_id}...")
        
        # 1. Build Protobuf Request
        # Pylance will error here, but it's correct at runtime
        req = pb.RequestOperation()
        req.operation.type = "changes"

        # Pylance will error here, but it's correct at runtime
        changes_req = pb.RecordZoneChangesRequest()
        changes_req.zone_id.zone_name = zone_id
        changes_req.sync_token = sync_token or ""
        # We can add desired_keys if needed, but for now, get everything
        
        req.record_zone_changes_request.CopyFrom(changes_req)

        # 2. Post and get response
        try:
            response_pb = self._post_operation(req)
            
            # Yield a single dictionary-like object for compatibility
            # with the old generator code.
            # A real implementation would loop here based on `more_coming`.
            changes_resp = response_pb.record_zone_changes_response
            yield {
                "records": changes_resp.changes, # Pass the RecordZoneChanges list
                "syncContinuationToken": changes_resp.sync_token,
                "moreComing": changes_resp.more_coming,
            }
            
            if changes_resp.more_coming:
                print("WARNING: More CloudKit changes available, but pagination "
                      "is not yet implemented in fetch_zone_changes.")
                
        except Exception as e:
            print(f"Error fetching zone changes: {e}")
            raise