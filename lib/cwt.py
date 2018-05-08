from ecdsa import SigningKey, VerifyingKey, NIST256p, NIST384p
from lib.cose import Signature1Message
from lib.cose.constants import Header, Key, Algorithm
from lib.cbor.constants import Keys as CK
from lib.edhoc.util import ecdsa_key_to_cose

from cbor2 import dumps, loads


def encode(claims: dict, key: SigningKey):
    protected = { Header.ALG: Algorithm.ES256 }
    unprotected = { Header.KID: b'my-secret-key' }

    msg = Signature1Message(payload=dumps(claims),
                            protected_header=dumps(protected),
                            unprotected_header=dumps(unprotected))

    return msg.serialize_signed(key)


def decode(encoded, key: VerifyingKey):
    return loads(Signature1Message.verify(encoded, key, external_aad=b''))
