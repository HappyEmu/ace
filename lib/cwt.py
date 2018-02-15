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
                            unprotected_header=unprotected)

    return msg.serialize_signed(key)


def decode(encoded, key: VerifyingKey):
    return loads(Signature1Message.verify(encoded, key, external_aad=b''))


def main():
    key = SigningKey.generate(curve=NIST256p)
    pk = key.get_verifying_key()

    cose_key = ecdsa_key_to_cose(pk, kid=b'you-know-that-one')

    claims = {
        CK.AUD: 'thatSensor01',
        CK.SCOPE: 'r',
        CK.IAT: 234234,
        CK.CNF: {
            Key.COSE_KEY: cose_key
        }
    }

    cwt = encode(claims, key)

    print(cwt.hex())

    payload = decode(cwt, pk)

    print(payload.hex())


if __name__ == '__main__':
    main()
