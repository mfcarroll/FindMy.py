import base64
import plistlib
import cbor2
import uuid
from typing import Optional
from miscreant.aes.siv import SIV

from . import crypto_util, asn1_defs
from .cloudkit_session import CloudKitSession
from . import cloudkit_pb2 as pb
from .constants import (
    PCS_ZONE_PROTECTED_STORAGE, ZONE_MANATEE, ZONE_ENGRAM,
    RECORD_TYPE_SYNCKEY, RECORD_TYPE_ITEM, RECORD_TYPE_CURRENT_ITEM,
    FINDMY_DEVICE_SECRET_ACCOUNT, FINDMY_SERVICE_NAME,
    CUTTLEFISH_ITEM_TYPE, CUTTLEFISH_PROTECTION_TAG
)

class KeychainAccess:
    """
    Manages fetching and decrypting iCloud Keychain items.
    Ported from the Rust `KeychainClient`.
    """
    def __init__(self, ck_session: CloudKitSession):
        self.ck_session = ck_session
        
        # Caches
        self.keystore = {}        # {key_id: pem_bytes} - Stores decrypted private keys
        self.pcs_keys = {}        # {key_id: record_dict} - Stores raw 'synckey' records
        self.keychain_items = {   # {zone: {uuid: record_dict}}
            ZONE_MANATEE: {},
            ZONE_ENGRAM: {},
            PCS_ZONE_PROTECTED_STORAGE: {}
        }
        self.sync_tokens = {}     # {zone: token_str}
        
        self.findmy_service_key_id = None

    def _get_field_value(self, record, field_name: str): # record type is protobuf, not dict
        """Helper to extract a value from a CloudKit protobuf record's 'fields' dict."""
        # Protobuf access is by attribute
        for field in record.fields:
            if field.identifier.name == field_name:
                return field.value
        return None

    def _get_b64_field(self, record, field_name: str) -> Optional[bytes]:
        """Helper for b64-encoded string fields."""
        val = self._get_field_value(record, field_name)
        # Protobuf stores b64 data in 'string_value'
        if val and val.HasField("string_value"): 
            return base64.b64decode(val.string_value)
        return None

    def _get_string_field(self, record, field_name: str) -> Optional[str]:
        """Helper for string fields."""
        val = self._get_field_value(record, field_name)
        if val and val.HasField("string_value"):
            return val.string_value
        return None
        
    def _get_ref_field(self, record, field_name: str):
        """Helper for reference fields."""
        val = self._get_field_value(record, field_name)
        if val and val.HasField("reference_value"):
            return val.reference_value
        return None

    def _fetch_pcs_key(self, key_id: str, zone_id: str = PCS_ZONE_PROTECTED_STORAGE):
        """Fetches a 'synckey' record from CloudKit if not in cache."""
        if key_id in self.pcs_keys:
            return self.pcs_keys[key_id]

        record_list = self.ck_session.fetch_records([key_id], zone_id)
        if not record_list:
            raise Exception(f"Failed to fetch PCS key: {key_id}")
        
        record = record_list[0] # fetch_records returns a list
        if record.record_type != RECORD_TYPE_SYNCKEY:
            raise Exception(f"Record {key_id} is not a synckey")
            
        self.pcs_keys[key_id] = record
        return record

    def get_decrypted_key(self, key_id: str, zone_id: str = PCS_ZONE_PROTECTED_STORAGE) -> bytes:
        """
        Recursively fetches and decrypts a PCS key, returning its PEM-encoded
        private key.
        """
        if key_id in self.keystore:
            return self.keystore[key_id]
        
        print(f"Decrypting key: {key_id}...")
        
        # 1. Fetch the raw 'synckey' record
        key_record = self._fetch_pcs_key(key_id, zone_id)
        
        # 2. Get its wrapped key and parent key reference
        wrapped_key = self._get_b64_field(key_record, "wrappedKey")
        parent_ref = self._get_ref_field(key_record, "parentKeyRef")
        
        if not wrapped_key or not parent_ref:
            raise Exception(f"Key {key_id} has no parent. It may be a root key "
                            f"that must be provided by the auth flow.")

        parent_key_id = parent_ref.record_identifier.record_name
        # wrapped_key is already bytes from _get_b64_field

        # 3. Recursively get the parent's private key (PEM)
        parent_private_key_pem = self.get_decrypted_key(parent_key_id, zone_id)

        # 4. Unwrap the key using RFC 6637
        fingerprint = b"fingerprint" 
        unwrapped_key_data = crypto_util.rfc6637_unwrap_key(
            parent_private_key_pem,
            wrapped_key,
            fingerprint
        )

        # 5. The unwrapped data is an ASN.1-encoded PCSPrivateKey
        pcs_key_struct = asn1_defs.PCSPrivateKey.load(unwrapped_key_data)
        
        # 6. Extract the actual private key (PKCS#8) and re-encode as PEM
        private_key_info = pcs_key_struct['privateKeyInfo']
        key_pem_bytes = private_key_info.dump(force=True)
        
        pem_output = b"-----BEGIN PRIVATE KEY-----\n"
        pem_output += base64.b64encode(key_pem_bytes)
        pem_output += b"\n-----END PRIVATE KEY-----"

        print(f"Successfully decrypted key: {key_id}")
        self.keystore[key_id] = pem_output
        return pem_output

    def sync_keychain_zone(self, zone_name: str):
        """Fetches all changes from a keychain zone and stores the items."""
        print(f"Syncing zone: {zone_name}...")
        try:
            last_token = self.sync_tokens.get(zone_name)
            new_token = None
            
            # The 'pages' here are the dicts yielded from the generator
            for page in self.ck_session.fetch_zone_changes(zone_name, last_token):
                # 'records' is a key in the yielded dict
                for record_change in page['records']:
                    record = record_change.record
                    record_name = record.record_identifier.record_name
                    
                    # Pylance will error here, but it's correct at runtime
                    if record_change.type == pb.RecordZoneChangesResponse.Change.DELETE:
                        self.keychain_items[zone_name].pop(record_name, None)
                    else: # CREATE or UPDATE
                        self.keychain_items[zone_name][record_name] = record
                
                new_token = page.get('syncContinuationToken')

            if new_token:
                self.sync_tokens[zone_name] = new_token
                print(f"Sync complete for {zone_name}. New token set.")
        
        except Exception as e:
            print(f"Failed to sync zone {zone_name}: {e}")

    def _build_aad(self, item_uuid_str: str, record) -> bytes:
        """
        Builds the Additional Authenticated Data (AAD) for Cuttlefish (v2)
        decryption.
        """
        item_uuid = uuid.UUID(item_uuid_str).bytes
        item_type = CUTTLEFISH_ITEM_TYPE
        protection_tag = CUTTLEFISH_PROTECTION_TAG

        data_plist_bytes = self._get_b64_field(record, "data")
        if not data_plist_bytes:
             raise ValueError("Item has no 'data' field for AAD")
        data_plist = plistlib.loads(data_plist_bytes)

        ctime = data_plist.get('ctime', 0)
        mtime = data_plist.get('mtime', 0)
        
        aad_data = [item_uuid, item_type, protection_tag, ctime, mtime]
        return cbor2.dumps(aad_data)

    def decrypt_keychain_item(self, item_uuid: str, record) -> Optional[dict]:
        """
        Decrypts a 'item' record (CuttlefishEncItem) using AES-SIV.
        """
        print(f"Decrypting keychain item: {item_uuid}")
        try:
            # 1. Parse the 'data' field, which is a b64-encoded plist
            data_plist_bytes = self._get_b64_field(record, "data")
            if not data_plist_bytes:
                raise ValueError("Item has no 'data' field")
            data_plist = plistlib.loads(data_plist_bytes)
            
            encver = data_plist.get('encver', 1)
            if encver != 2:
                raise NotImplementedError(f"Only Cuttlefish v2 (AES-SIV) supported. Found v{encver}")

            # 2. Get the item's wrapped key and parent ref
            wrapped_key = self._get_b64_field(record, "wrappedKey")
            parent_ref = self._get_ref_field(record, "parentKeyRef")
            
            # --- FIX: Fix typo and add None checks ---
            if not wrapped_key or not parent_ref:
                raise ValueError("Item is missing wrappedKey or parentKeyRef")

            if not parent_ref.record_identifier:
                raise ValueError("Parent ref is missing record_identifier")
            if not parent_ref.zone_identifier:
                raise ValueError("Parent ref is missing zone_identifier")
            # --- END FIX ---

            parent_key_id = parent_ref.record_identifier.record_name
            parent_zone_id = parent_ref.zone_identifier.zone_name

            # 3. Get the parent key (unwrapping key)
            unwrapping_key_pem = self.get_decrypted_key(parent_key_id, parent_zone_id)
            
            # 4. Unwrap the item's data key
            data_key = crypto_util.rfc6637_unwrap_key(
                unwrapping_key_pem,
                wrapped_key,
                b"fingerprint"
            )
            
            # 5. Get the encrypted data (v_Data)
            encrypted_data_with_tag = data_plist['v_Data'] # This is bytes from plist

            # 6. Build the AAD
            aad = self._build_aad(item_uuid, record)
            
            # 7. Decrypt using AES-SIV
            siv = SIV(data_key)
            decrypted_data = siv.open(encrypted_data_with_tag, [aad])
            
            # 8. The decrypted data is another plist
            final_plist = plistlib.loads(decrypted_data)
            print(f"Successfully decrypted item: {item_uuid}")
            return final_plist

        except Exception as e:
            print(f"Failed to decrypt item {item_uuid}: {e}")
            return None

    def _find_findmy_service_key(self):
        """
        Finds the service key for FindMy by searching synced PCS items.
        """
        if self.findmy_service_key_id:
            return self.findmy_service_key_id
            
        print("Searching for FindMy service key...")
        # We must iterate the PCS zone items, not just keys we've decrypted
        for key_id, record in self.keychain_items[PCS_ZONE_PROTECTED_STORAGE].items():
            if record.record_type != RECORD_TYPE_SYNCKEY:
                continue
                
            service_name = self._get_string_field(record, "service")
            if service_name == FINDMY_SERVICE_NAME:
                print(f"Found FindMy service key: {key_id}")
                self.findmy_service_key_id = key_id
                return key_id
        
        print("Warning: FindMy service key not found in synced PCS zone.")
        return None

    def get_device_secrets(self):
        """
        The main public method.
        Syncs all zones and finds/decrypts FindMy device secrets.
        """
        if "MasterKey" not in self.keystore:
            raise Exception("Keystore does not contain 'MasterKey'. "
                            "Please seed the keystore from your login flow.")

        # 1. Sync all relevant zones
        self.sync_keychain_zone(PCS_ZONE_PROTECTED_STORAGE)
        self.sync_keychain_zone(ZONE_MANATEE)
        self.sync_keychain_zone(ZONE_ENGRAM)
        
        # 2. Find the FindMy service key
        findmy_service_key_id = self._find_findmy_service_key()
        if not findmy_service_key_id:
            raise Exception("Could not locate FindMy service key.")
            
        # This will recursively decrypt the service key using the MasterKey
        self.get_decrypted_key(findmy_service_key_id, PCS_ZONE_PROTECTED_STORAGE)

        # 3. Find and decrypt the actual device secrets in the Manatee zone
        secrets = []
        for item_uuid, record in self.keychain_items[ZONE_MANATEE].items():
            if record.record_type != RECORD_TYPE_ITEM:
                continue

            try:
                data_plist_bytes = self._get_b64_field(record, "data")
                if not data_plist_bytes:
                    continue
                data_plist = plistlib.loads(data_plist_bytes)
                account_name = data_plist.get('acct')
                
                if account_name == FINDMY_DEVICE_SECRET_ACCOUNT:
                    print(f"Found potential secret: {item_uuid}")
                    
                    parent_ref = self._get_ref_field(record, "parentKeyRef")
                    if parent_ref and parent_ref.record_identifier.record_name == findmy_service_key_id:
                        decrypted_item = self.decrypt_keychain_item(item_uuid, record)
                        if decrypted_item:
                            secrets.append(decrypted_item)
                    else:
                        print(f"Skipping {item_uuid}, not chained to FindMy key.")
                        
            except Exception as e:
                print(f"Error processing item {item_uuid}: {e}")

        return secrets