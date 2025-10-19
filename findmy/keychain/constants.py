# Constants ported from the Rust implementation

# OID for P-256 curve, used in RFC 6637 KDF
P256_OID = b'\x2a\x86\x48\xce\x3d\x03\x01\x07'

# Keychain zones
PCS_ZONE_PROTECTED_STORAGE = "_PCS"
ZONE_MANATEE = "Manatee"
ZONE_ENGRAM = "Engram"

# Record types
RECORD_TYPE_SYNCKEY = "synckey"
RECORD_TYPE_ITEM = "item"
RECORD_TYPE_CURRENT_ITEM = "currentitem"

# PCS Service Names
PCS_MASTER_KEY_SERVICE = "MasterKey"
PCS_SERVICE_KEY_SERVICE = "SERVICE"

# FindMy Account/Service identifiers
FINDMY_DEVICE_SECRET_ACCOUNT = "com.apple.findmy.DeviceSecret"
FINDMY_SERVICE_NAME = "com.apple.private.findmy" # Used to find the service key

# Cuttlefish (keychain item) constants
CUTTLEFISH_ITEM_TYPE = b"item"
CUTTLEFISH_PROTECTION_TAG = b"user"