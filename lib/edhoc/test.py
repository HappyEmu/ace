from ecdsa import SigningKey, VerifyingKey, NIST384p

import os

from lib.edhoc.message import Message1, Message2


def gen_64bit_nonce():
    return os.urandom(64 // 8)


if __name__ == '__main__':
    sk = SigningKey.generate(curve=NIST384p)
    vk = sk.get_verifying_key()

    msg_send = Message1(session_id=b'1234', nonce=gen_64bit_nonce(), key=vk)
    cbor = msg_send.serialize()
    msg_rvcd = Message1.deserialize(cbor)

    sig = sk.sign_deterministic(b'Hello World')
    print(sig)

    msg_rvcd.key.verify(sig, b'Hello World')

