from cbor2 import loads, dumps
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


from lib.cose import Encrypt0Message
from lib.cose.constants import Header

backend = default_backend()


class OscoreContext:

    def __init__(self, secret: bytes, salt: bytes, sid: bytes, rid: bytes):
        self.master_secret = secret
        self.master_salt = salt
        self.sender_id = sid
        self.recipient_id = rid
        self.sequence_number = 0

    def encrypt(self, payload: bytes):
        piv = bytes([self.sequence_number])
        kid = self.sender_id

        protected_header = b''
        unprotected_header = {Header.PARTIAL_IV: piv,
                              Header.KID: kid}

        # Compute sender key and nonce for this particular message
        key = self.sender_key()
        nonce = bytes([len(self.sender_id)]) + self.sender_id.rjust(7, b'\0') + bytes([self.sequence_number]).rjust(5, b'\0')
        nonce = bxor(nonce, self.common_iv())

        # Increase sequence number => nonce is always unique
        self.sequence_number += 1

        aad = dumps([piv, kid])

        # Encrypt message
        return Encrypt0Message(
            plaintext=payload,
            protected_header=protected_header,
            unprotected_header=unprotected_header,
            external_aad=aad
        ).serialize(iv=nonce, key=key)

    def decrypt(self, encoded: bytes):
        # Extract Partial IV (piv) and kid (recipient_id)
        prot, unprot, cipher = loads(encoded).value
        piv = unprot[Header.PARTIAL_IV]
        kid = unprot[Header.KID]

        aad = dumps([piv, kid])

        # Compute Key and Nonce for message
        key = self.recipient_key()
        nonce = bytes([len(self.recipient_id)]) + self.recipient_id.rjust(7, b'\0') + piv.rjust(5, b'\0')
        nonce = bxor(nonce, self.common_iv())

        # Decrypt message
        return Encrypt0Message.decrypt(
            encoded,
            iv=nonce,
            key=key,
            external_aad=aad
        )

    def __str__(self):
        return f'OSCORE context (master_secret={self.master_secret.hex()}, master_salt={self.master_salt.hex()})'

    def sender_key(self):
        # derive sender CEK
        # CEK = hkdf(master_salt, master_secret, [sender_id, 12, "Key", 16])
        info = dumps([self.sender_id, 10, "Key", 16])
        return HKDF(hashes.SHA256(), 16, self.master_salt, info, backend).derive(self.master_secret)

    def recipient_key(self):
        # derive recipient CEK
        # CEK = hkdf(master_salt, master_secret, [recipient_id, 12, "Key", 16])
        info = dumps([self.recipient_id, 10, "Key", 16])
        return HKDF(hashes.SHA256(), 16, self.master_salt, info, backend).derive(self.master_secret)

    def common_iv(self):
        # derive Common IV
        # CIV = hkdf(master_salt, master_secret, [b'', 12, "IV", 7])
        info = dumps([b'', 10, "IV", 13])
        return HKDF(hashes.SHA256(), 13, self.master_salt, info, backend).derive(self.master_secret)


def bxor(a: bytes, b: bytes) -> bytes:
    return bytes([i^j for i,j in zip(a, b)])