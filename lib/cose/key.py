from cbor2 import loads

from lib.cose.constants import Key
from lib.edhoc.util import ecdsa_cose_to_key, ecdh_cose_to_key, ecdsa_key_to_cose, ecdh_key_to_cose


class CoseKey:

    class Type:
        ECDSA = 1
        ECDHE = 2

    def __init__(self, key, key_id, ktype: Type):
        self.key = key
        self.key_id = key_id
        self.ktype = ktype

    def encode(self):
        if self.ktype == CoseKey.Type.ECDSA:
            return ecdsa_key_to_cose(self.key, kid=self.key_id)
        if self.ktype == CoseKey.Type.ECDHE:
            return ecdh_key_to_cose(self.key, kid=self.key_id)
        else:
            return None

    @classmethod
    def from_cose(cls, encoded: bytes, ktype: Type = Type.ECDSA):
        decoded = loads(encoded)

        key_id = decoded[Key.KID]

        if ktype == CoseKey.Type.ECDSA:
            key = ecdsa_cose_to_key(encoded)
        else:
            key = ecdh_cose_to_key(encoded)

        return CoseKey(key, key_id, ktype)
