from cbor2 import loads, dumps, CBORTag as Tag
from jwcrypto import jwk
import json as j
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


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


class ECDSA:
    ES256 = -7
    ES384 = -35
    ES512 = -36


signature_algorithms = ['ES256', 'ES384', 'ES521']


def signature1_message(payload: bytes, key: jwk.JWK, alg: int):
    protected_header = { CoseHeader.ALG: ECDSA.ES256}
    unprotected_header = { CoseHeader.KID: b'AsymmetricECDSA256' }

    signature = _create_signature(context="Signature1",
                                  body_protected=dumps(protected_header),
                                  payload=payload,
                                  external_aad=b'',
                                  key=key)
    # Note: signature is not stable even if signature data is stable, RNG in ECDSA

    cose_sign1 = [
        protected_header,
        unprotected_header,
        payload,
        signature,
    ]

    dumps(Tag(MessageTypes.COSE_SIGN1, cose_sign1))


def _create_signature(context: str,
                      body_protected: bytes,
                      payload: bytes,
                      key: jwk.JWK,
                      external_aad: bytes,
                      alg: 'str' = 'ES256',
                      sign_protected: bytes = None) -> bytes:
    if sign_protected is not None:
        sign_structure = [context, body_protected, sign_protected, external_aad, payload]
    else:
        sign_structure = [context, body_protected, external_aad, payload]

    to_sign = dumps(sign_structure)

    signature_key = key.get_op_key('sign')
    signature = signature_key.sign(to_sign, ec.ECDSA(hashes.SHA256()))

    return signature


if __name__ == '__main__':
    payload = {1: 'coap://as.example.com',
               2: 'erikw',
               3: 'coap://light.example.com',
               4: 1444064944,
               5: 1443944944,
               6: 1443944944,
               7: bytes.fromhex('0b71')}

    json = """{
                "kty":"EC",
                "kid":"11",
                "crv":"P-256",
                "x":"usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y":"IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d":"V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"
             }"""

    key = jwk.JWK(**j.loads(json))

    signature1_message(payload=dumps("This is the content."), key=key, alg=None)