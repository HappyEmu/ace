from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from ecdsa import SigningKey, VerifyingKey, NIST256p
from cbor2 import dumps
import os
from lib.cose import CoseKey

backend = default_backend()


def derive_key(input_key: bytes, length: int, context_info: bytes):
    # length is in bytes
    hkdf = HKDF(algorithm=hashes.SHA256(),
                length=length,
                salt=None,
                info=context_info,
                backend=backend)

    return hkdf.derive(input_key)


def cose_kdf_context(algorithm_id: str, key_length: int, other: bytes):
    # key_length is in bytes
    return dumps([
        algorithm_id,
        [None, None, None], # PartyUInfo
        [None, None, None], # PartyVInfo
        [key_length, b'', other] # SuppPubInfo
    ])


def message_digest(message: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=backend)
    digest.update(message)
    return digest.finalize()


def cose_key(key) -> bytes:
    params = key.public_numbers()

    curve = params.curve.name
    x = params.x
    y = params.y

    cbor = {
        CoseKey.KTY: CoseKey.Type.EC2,
        CoseKey.CRV: CoseKey.Curves.P_256,
        CoseKey.X: x,
        CoseKey.Y: y
    }

    return dumps(cbor)


def transfer(src, dest, args):
    pass


def main():
    # U
    s_u = os.urandom(2)
    n_u = os.urandom(8)

    sk_u = SigningKey.generate(curve=NIST256p)
    vk_u = sk_u.get_verifying_key()

    secret_u = ec.generate_private_key(ec.SECP256R1, backend)
    e_u = secret_u.public_key()

    transfer('U', 'V', (s_u, n_u, e_u))

    # V
    s_v = os.urandom(2)
    n_v = os.urandom(8)

    sk_v = SigningKey.generate(curve=NIST256p)
    vk_v = sk_v.get_verifying_key()

    secret_v = ec.generate_private_key(ec.SECP256R1, backend)
    ecdh_shared_secret_v = secret_v.exchange(ec.ECDH(), e_u)
    e_v = secret_v.public_key()
    k_2_v = derive_key(ecdh_shared_secret_v, 16, context_info=cose_kdf_context("AES-CCM-64-64-128", 16, other=b'asdf'))

    transfer('V', 'U', (s_u, s_v, n_v, e_v))

    # U
    ecdh_shared_secret_u = secret_u.exchange(ec.ECDH(), e_v)
    k_2_u = derive_key(ecdh_shared_secret_u, 16, context_info=cose_kdf_context("AES-CCM-64-64-128", 16, other=b'asdf'))
    k_3_u = derive_key(ecdh_shared_secret_u, 16, context_info=cose_kdf_context("AES-CCM-64-64-128", 16, other=b'asdfasdf'))

    assert ecdh_shared_secret_u == ecdh_shared_secret_v
    assert k_2_u == k_2_v

    # V
    k_3_v = derive_key(ecdh_shared_secret_v, 16, context_info=cose_kdf_context("AES-CCM-64-64-128", 16, other=b'asdfasdf'))
    assert k_3_u == k_3_v

    # =========== #
    

    print(ecdh_shared_secret_u.hex())
    print(ecdh_shared_secret_v.hex())

    print(cose_key(e_u).hex())



if __name__ == '__main__':
    main()
