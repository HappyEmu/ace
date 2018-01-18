import jwt
import os

from jwcrypto import jwk
from lib.cbor.constants import Keys as CK
from jwcrypto.common import json_decode


class AccessToken:

    def __init__(self, claims: dict):
        self._reference: str = os.urandom(16).hex()
        self._claims = claims
        self._bound_key = None

    def bind_key(self, key: jwk.JWK):
        self._bound_key = key

        # Add CNF Claim to bind key to this access token
        self._claims.update({
            CK.CNF: {'COSE_KEY': json_decode(key.export())}
        })

    def sign_and_export_self_contained(self, key) -> str:
        return jwt.encode(payload=self._claims, key=key, algorithm='HS256').decode('utf-8')

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
    def bound_key(self) -> jwk.JWK:
        return self._bound_key

    @property
    def reference(self) -> str:
        return self._reference

    @property
    def claims(self) -> dict:
        return self._claims

