from asn1crypto import core, keys

# These definitions are ported from the `rasn` structs in pcs.rs
# They describe the structure of the data stored in 'synckey' records.

class Key(core.OctetString):
    pass

class WrappedKey(core.Sequence):
    _fields = [
        ('version', core.Integer),
        ('key_class', core.Integer),
        ('key_data', Key),
        ('wrapped_key', core.OctetString, {'optional': True}),
    ]

class PCSPrivateKey(core.Sequence):
    """
    The main structure for a PCS private key, which is itself
    wrapped and stored inside a 'synckey' record's 'wrappedKey' field
    after being unwrapped by its parent.
    """
    _fields = [
        ('version', core.Integer),
        ('algorithm', core.ObjectIdentifier),
        ('privateKeyInfo', keys.PrivateKeyInfo),
        ('wrappedKey', WrappedKey, {'optional': True}),
        ('service', core.PrintableString, {'optional': True}),
    ]