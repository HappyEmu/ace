from ecdsa import SigningKey, VerifyingKey, NIST256p
from lib.cose import Signature1Message
from lib.cose.constants import Header, Key, Algorithm
from lib.cbor.constants import Keys as CK

from cbor2 import dumps


def encode(claims: dict, key: SigningKey):
    protected = { Header.ALG: Algorithm.ES256 }
    unprotected = { Header.KID: b'my-secret-key' }

    msg = Signature1Message(payload=dumps(claims),
                            protected_header=dumps(protected),
                            unprotected_header=unprotected)

    return msg.serialize_signed(key)


def decode(encoded, key: VerifyingKey):
    return Signature1Message.verify(encoded, key, external_aad=b'')


def main():
    key = SigningKey.generate(curve=NIST256p)
    pk = key.get_verifying_key()

    claims = {
        CK.AUD: 'thatSensor01',
        CK.SCOPE: 'r',
        CK.IAT: 234234,
        CK.CNF: {
            Key.COSE_KEY: {
                Key.X: 892375980347529384752093485703294857239485720394857345,
                Key.Y: 928374590823475029348752930845720398457230948572309458,
                Key.CRV: Key.Curve.P_256,
                Key.KID: b'you-know-that-one'
            }
        }
    }

    cwt = encode(claims, key)

    print(cwt.hex())

    payload = decode(cwt, pk)

    print(payload.hex())


if __name__ == '__main__':
    main()
