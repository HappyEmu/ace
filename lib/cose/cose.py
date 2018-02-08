import hashlib
from typing import Union

from cbor2 import loads, dumps, CBORTag as Tag
from ecdsa import SigningKey, VerifyingKey, NIST192p, NIST256p

from cryptography.hazmat.primitives.ciphers.aead import AESCCM


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


class Algorithms:
    ES256 = -7
    ES384 = -35
    ES512 = -36
    AES_CCM_16_64_128 = 10
    AES_CCM_64_64_128 = 12


signature_algorithms = ['ES256', 'ES384', 'ES521']


class Signature1Message:

    def __init__(self, payload: bytes=b'', external_aad: bytes=b''):
        self.payload = payload
        self.external_aad = external_aad

    def serialize_signed(self, key: SigningKey) -> bytes:
        protected_header = {CoseHeader.ALG: Algorithms.ES256}
        unprotected_header = {CoseHeader.KID: b'AsymmetricECDSA256'}

        signature = self._create_signature(context="Signature1",
                                           body_protected=dumps(protected_header),
                                           payload=self.payload,
                                           external_aad=self.external_aad,
                                           key=key)
        cose_sign1 = [
            protected_header,
            unprotected_header,
            self.payload,
            signature,
        ]

        return dumps(Tag(MessageTypes.COSE_SIGN1, cose_sign1))

    def _create_signature(self,
                          context: str,
                          body_protected: bytes,
                          payload: bytes,
                          key: SigningKey,
                          external_aad: bytes,
                          sign_protected: bytes = None) -> bytes:

        if sign_protected is not None:
            sign_structure = [context, body_protected, sign_protected, external_aad, payload]
        else:
            sign_structure = [context, body_protected, external_aad, payload]

        to_sign = dumps(sign_structure)

        signature = key.sign_deterministic(to_sign, hashlib.sha256)

        return signature


class Encrypt0Message:

    def __init__(self, plaintext: bytes, external_aad: bytes = b''):
        self.plaintext = plaintext
        self.external_aad = external_aad

    def serialize(self, iv: bytes, key: bytes):
        protected_header = {CoseHeader.ALG: Algorithms.AES_CCM_64_64_128}
        unprotected_header = {CoseHeader.IV: iv}

        enc_structure = ["Encrypt0", dumps(protected_header), self.external_aad ]
        aad = dumps(enc_structure)

        # key = AESCCM.generate_key(bit_length=128)
        ciphertext = self._encrypt(key, iv, aad=aad)

        cose_encrypt0 = [protected_header, unprotected_header, ciphertext]

        return dumps(Tag(MessageTypes.COSE_ENCRYPT0, cose_encrypt0))


    # AES-CCM-64-64-128 = AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce
    def _encrypt(self, key: bytes, iv: bytes, aad: bytes):
        cipher = AESCCM(key, tag_length=8)
        ciphertext = cipher.encrypt(nonce=iv, data=self.plaintext, associated_data=aad)

        return ciphertext


def main():
    plaintext = b"This is the content."

    iv = bytes.fromhex("89F52F65A1C580")
    key = bytes.fromhex("849B57219DAE48DE646D07DBB533566E")

    msg = Encrypt0Message(plaintext, b'')
    cbor = msg.serialize(iv, key)
    print(cbor.hex())


if __name__ == '__main__':
    main()
