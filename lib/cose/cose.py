import hashlib
from typing import Union

from cbor2 import loads, dumps, CBORTag as Tag
from ecdsa import SigningKey, VerifyingKey, NIST192p, NIST256p
import json as j


class MessageTypes:
    """
    COSE Message Type Tags
    """
    COSE_SIGN     = 98
    COSE_SIGN1    = 18
    COSE_ENCRYPT  = 96
    COSE_ENCRYPT0 = 16
    COSE_MAC      = 97
    COSE_MAC0     = 17


class CoseHeader:
    """
    COSE Common Header Parameters: Name - Label
    """
    ALG               = 1   # int / tstr
    CRIT              = 2
    CONTENT_TYPE      = 3   # tstr / uint
    KID               = 4   # bstr
    IV                = 5   # bstr
    PARTIAL_IV        = 6   # bstr
    COUNTER_SIGNATURE = 7   # COSE_Signature


class ECDSA_COSE:
    ES256 = -7
    ES384 = -35
    ES512 = -36


signature_algorithms = ['ES256', 'ES384', 'ES521']


class Signature1Message:

    def __init__(self, payload: bytes, external_aad: bytes=None):
        self.payload = payload
        self.external_aad = external_aad

    def serialize_signed(self, key: SigningKey) -> bytes:
        protected_header = {CoseHeader.ALG: ECDSA_COSE.ES256}
        unprotected_header = {CoseHeader.KID: b'AsymmetricECDSA256'}

        signature = self._create_signature(context="Signature1",
                                           body_protected=dumps(protected_header),
                                           payload=self.payload,
                                           external_aad=self.external_aad,
                                           key=key)
        cose_sign1 = [
            protected_header,
            unprotected_header,
            self.payload,
            signature,
        ]

        return dumps(Tag(MessageTypes.COSE_SIGN1, cose_sign1))

    def _create_signature(self,
                          context: str,
                          body_protected: bytes,
                          payload: bytes,
                          key: SigningKey,
                          external_aad: bytes,
                          sign_protected: bytes = None) -> bytes:

        # EAAD and payload should be empty binary string if not present
        external_aad = b'' if external_aad is None else external_aad
        payload = b'' if payload is None else payload

        if sign_protected is not None:
            sign_structure = [context, body_protected, sign_protected, external_aad, payload]
        else:
            sign_structure = [context, body_protected, external_aad, payload]

        to_sign = dumps(sign_structure)

        signature = key.sign_deterministic(to_sign, hashlib.sha256)

        return signature


def main():
    payload = "Hello WOrlasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfsdfasdfasdfdasdfasdf"

    key = SigningKey.generate(curve=NIST256p, hashfunc=hashlib.sha256)

    sig = Signature1Message(payload=dumps(payload), external_aad=None)

    print(len(sig.serialize_signed(key)))


if __name__ == '__main__':
    main()
