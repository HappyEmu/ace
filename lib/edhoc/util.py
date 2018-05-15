from cbor2 import dumps, loads

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec as curves
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers

from ecdsa import curves as ecdsa_curves, VerifyingKey, ellipticcurve

from lib.cose.constants import Key as CoseKey

backend = default_backend()

_ecdh_curves = {
    CoseKey.Curve.P_256: curves.SECP256R1,
    CoseKey.Curve.P_384: curves.SECP384R1,
    CoseKey.Curve.P_521: curves.SECP521R1
}

_ecdh_names = {
    'secp256r1': CoseKey.Curve.P_256,
    'secp384r1': CoseKey.Curve.P_384,
    'secp521r1': CoseKey.Curve.P_521
}

_ecdsa_curves = {
    CoseKey.Curve.P_256: ecdsa_curves.NIST256p,
    CoseKey.Curve.P_384: ecdsa_curves.NIST384p,
    CoseKey.Curve.P_521: ecdsa_curves.NIST521p
}

_ecdsa_names = {
    "NIST256p": CoseKey.Curve.P_256,
    "NIST384p": CoseKey.Curve.P_384,
    "NIST521p": CoseKey.Curve.P_521
}


def ecdh_key_to_cose(key, kid: bytes = None, encode=True):
    params = key.public_numbers()

    curve = _ecdh_names[params.curve.name]
    x = params.x
    y = params.y

    cbor = {
        CoseKey.KTY: CoseKey.Type.EC2,
        CoseKey.CRV: curve,
        CoseKey.X: bytes.fromhex(format(x, 'x').zfill(64)),
        CoseKey.Y: bytes.fromhex(format(y, 'x').zfill(64))
    }

    if kid is not None:
        cbor.update({CoseKey.KID: kid})

    if encode:
        return dumps(cbor)
    else:
        return cbor


def ecdh_cose_to_key(ckey: bytes):
    decoded = loads(ckey)

    kty = decoded[CoseKey.KTY]
    curve = _ecdh_curves[decoded[CoseKey.CRV]]
    x = int(decoded[CoseKey.X].hex(), 16)
    y = int(decoded[CoseKey.Y].hex(), 16)

    numbers = EllipticCurvePublicNumbers(x, y, curve())

    key = backend.load_elliptic_curve_public_numbers(numbers)

    return key


def ecdsa_key_to_cose(key: VerifyingKey, kid: bytes = None, encode=True):
    curve = _ecdsa_names[key.curve.name]
    x = key.pubkey.point.x()
    y = key.pubkey.point.y()

    cbor = {
        CoseKey.KTY: CoseKey.Type.EC2,
        CoseKey.CRV: curve,
        CoseKey.X: bytes.fromhex(format(x, 'x').zfill(64)),
        CoseKey.Y: bytes.fromhex(format(y, 'x').zfill(64))
    }

    if kid is not None:
        cbor.update({CoseKey.KID: kid})

    if encode:
        return dumps(cbor)
    else:
        return cbor


def ecdsa_cose_to_key(encoded: bytes) -> VerifyingKey:
    decoded = loads(encoded)

    kty = decoded[CoseKey.KTY]
    curve = _ecdsa_curves[decoded[CoseKey.CRV]]
    x = int(decoded[CoseKey.X].hex(), 16)
    y = int(decoded[CoseKey.Y].hex(), 16)

    p = ellipticcurve.Point(curve.curve, x, y)
    key = VerifyingKey.from_public_point(p, curve)

    return key


def vk_from_point(x: bytes, y: bytes):
    curve = ecdsa_curves.NIST256p
    x = int(x.hex(), 16)
    y = int(y.hex(), 16)

    p = ellipticcurve.Point(curve.curve, x, y)
    key = VerifyingKey.from_public_point(p, curve)

    return key
