from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP256R1
from cryptography.hazmat.primitives.asymmetric import ec as curves

from cbor2 import dumps, loads
from lib.cose import CoseKey

backend = default_backend()

_curves = {
    CoseKey.Curves.P_256: curves.SECP256R1,
    CoseKey.Curves.P_384: curves.SECP384R1,
    CoseKey.Curves.P_521: curves.SECP521R1
}

_names = {
    'secp256r1': CoseKey.Curves.P_256,
    'secp384r1': CoseKey.Curves.P_384,
    'secp521r1': CoseKey.Curves.P_521
}


def key_to_cose(key):
    params = key.public_numbers()

    curve = _names[params.curve.name]
    x = params.x
    y = params.y

    cbor = {
        CoseKey.KTY: CoseKey.Type.EC2,
        CoseKey.CRV: curve,
        CoseKey.X: x,
        CoseKey.Y: y
    }

    return dumps(cbor)


def cose_to_key(ckey):
    decoded = loads(ckey)

    kty = decoded[CoseKey.KTY]
    curve = _curves[decoded[CoseKey.CRV]]
    x = decoded[CoseKey.X]
    y = decoded[CoseKey.Y]

    numbers = EllipticCurvePublicNumbers(x, y, curve())

    key = backend.load_elliptic_curve_public_numbers(numbers)

    return key


if __name__ == '__main__':
    cose_to_key({
        CoseKey.KTY: CoseKey.Type.EC2,
        CoseKey.CRV: CoseKey.Curves.P_256,
        CoseKey.X: 26987828860639459741275148105927727866567532987005391635620339733914939250266,
        CoseKey.Y: 13201145698279263754542295514768112958052299740361512657822153071594243777460
    })
