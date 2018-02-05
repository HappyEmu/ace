from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import cryptography.hazmat.primitives.asymmetric.utils as utils

from jwcrypto import jwk, jws
from jwcrypto.common import json_decode

import hashlib as hash
from ecdsa import SigningKey, curves


def hazmat():
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    data = b"this is some data I'd like to sign"
    (r, s) = utils.decode_dss_signature(private_key.sign(data, ec.ECDSA(hashes.SHA256())))
    print((r,s))


def jwcrypto(pem):
    private_key = jwk.JWK()
    private_key.import_from_pem(pem)

    tok = jws.JWS(b'Hello World')
    tok.add_signature(private_key, alg='ES256')

    return tok.serialize(compact=True)

def ecdsa(pem):
    sk = SigningKey.from_pem(pem.decode('utf-8'))
    vk = sk.get_verifying_key()

    sig = sk.sign(b"Hello World")
    vk.verify(sig, b"Hello World")


if __name__ == '__main__':


    pem = bytes("""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBtcRjAg0UCbELwFZ+qnbzTD9wTz7vTynwq4eToMVn1voAoGCCqGSM49
AwEHoUQDQgAEaLfuNZ7jCp7nMrJpWETlxh/EZqH/FHF6I2PDNsLJb4xtaR0UE2fW
yHyTH7qo+J4f0gy8dusuBYjBVl2kPSoU7A==
-----END EC PRIVATE KEY-----""", encoding='utf-8')

    token = ecdsa(pem)



