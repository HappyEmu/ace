import os

from lib.cbor.constants import Keys as CK
from lib.cose.constants import Key
from lib.cose import CoseKey
import lib.cwt as cwt
from ecdsa import SigningKey


class AccessToken:

    def __init__(self, claims: dict):
        self._reference: str = os.urandom(16).hex()
        self._claims = claims
        self._bound_key = None

    def bind_key(self, key: CoseKey):
        self._bound_key = key

        # Add CNF Claim to bind key to this access token
        self._claims.update({
            CK.CNF: { Key.COSE_KEY: key.encode()}
        })

    def sign_and_export_self_contained(self, key: SigningKey, key_id: bytes) -> str:
        return cwt.encode(self._claims, key, key_id)

    def export_referential(self):
        return self.reference

    @property
    def issuer(self) -> str:
        return self._claims[CK.ISS]

    @property
    def cti(self) -> str:
        return self._claims[CK.CTI]

    @property
    def audience(self) -> str:
        return self._claims[CK.AUD]

    @property
    def scope(self) -> str:
        return self._claims[CK.SCOPE]

    @property
    def expires(self) -> int:
        return self._claims[CK.EXP]

    @property
    def issued_at(self) -> int:
        return self._claims[CK.IAT]

    @property
    def bound_key(self) -> CoseKey:
        return self._bound_key

    @property
    def reference(self) -> str:
        return self._reference

    @property
    def claims(self) -> dict:
        return self._claims

