import hashlib

from cbor2 import loads, dumps, CBORTag
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from ecdsa import SigningKey, VerifyingKey

from lib.cose.constants import Header, Tag, Algorithm

signature_algorithms = ['ES256', 'ES384', 'ES521']


class SignatureVerificationFailed(Exception):
    pass


class Signature1Message:

    def __init__(self,
                 payload: bytes=b'',
                 external_aad: bytes=b'',
                 protected_header: bytes=None,
                 unprotected_header: dict=None):

        self.payload = payload
        self.external_aad = external_aad
        self.protected_header = b'' if protected_header is None else protected_header
        self.unprotected_header = unprotected_header

    def serialize_signed(self, key: SigningKey) -> bytes:
        signature = Signature1Message.create_signature(context="Signature1",
                                                       body_protected=self.protected_header,
                                                       payload=self.payload,
                                                       external_aad=self.external_aad,
                                                       key=key)
        cose_sign1 = [
            self.protected_header,
            self.unprotected_header,
            self.payload,
            signature,
        ]

        return dumps(CBORTag(Tag.COSE_SIGN1, cose_sign1))

    @classmethod
    def create_signature(cls,
                         context: str,
                         body_protected: bytes,
                         payload: bytes,
                         key: SigningKey,
                         external_aad: bytes,
                         sign_protected: bytes = None) -> bytes:

        sign_structure = Signature1Message.sign_structure(context,
                                                          body_protected,
                                                          payload,
                                                          external_aad,
                                                          sign_protected)

        to_sign = dumps(sign_structure)

        signature = key.sign_deterministic(to_sign, hashlib.sha256)

        return signature

    @classmethod
    def sign_structure(cls, context: str,
                       body_protected: bytes,
                       payload: bytes,
                       external_aad: bytes,
                       sign_protected: bytes = None):

        if sign_protected is not None:
            sign_structure = [context, body_protected, sign_protected, external_aad, payload]
        else:
            sign_structure = [context, body_protected, external_aad, payload]

        return sign_structure

    @classmethod
    def verify(cls, encoded, key: VerifyingKey, external_aad: bytes):
        decoded = loads(encoded)

        tag = decoded.tag
        (protected, unprotected, payload, signature) = decoded.value

        sign_structure = Signature1Message.sign_structure("Signature1", protected, payload, external_aad)
        to_verify = dumps(sign_structure)

        if not key.verify(signature, to_verify, hashlib.sha256):
            raise SignatureVerificationFailed()

        return payload


class Encrypt0Message:

    def __init__(self, plaintext: bytes, external_aad: bytes = b''):
        self.plaintext = plaintext
        self.external_aad = external_aad

    def serialize(self, iv: bytes, key: bytes):
        protected_header = { Header.ALG: Algorithm.AES_CCM_64_64_128 }
        unprotected_header = { Header.IV: iv }

        enc_structure = Encrypt0Message.enc_structure(protected_header, self.external_aad)
        aad = dumps(enc_structure)

        ciphertext = self._encrypt(key, iv, aad=aad)

        cose_encrypt0 = [protected_header, unprotected_header, ciphertext]

        return dumps(CBORTag(Tag.COSE_ENCRYPT0, cose_encrypt0))


    # AES-CCM-64-64-128 = AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce
    def _encrypt(self, key: bytes, iv: bytes, aad: bytes):
        cipher = AESCCM(key, tag_length=8)
        ciphertext = cipher.encrypt(nonce=iv, data=self.plaintext, associated_data=aad)

        return ciphertext

    @classmethod
    def enc_structure(cls, protected, external_aad):
        return ["Encrypt0", dumps(protected), external_aad]

    @classmethod
    def decrypt(cls, encoded: bytes, key: bytes, iv: bytes, external_aad: bytes):
        decoded = loads(encoded)

        tag = decoded.tag
        (protected, unprotected, ciphertext) = decoded.value

        aad = dumps(Encrypt0Message.enc_structure(protected, external_aad))

        cipher = AESCCM(key, tag_length=8)
        plaintext = cipher.decrypt(nonce=iv, data=ciphertext, associated_data=aad)

        return plaintext


def main():
    plaintext = b"This is the contentasvasmndbfvasmnbdfvasnbdvfasmdfasdmfnbsdvf"

    iv = bytes.fromhex("89F52F65A1C580")
    key = bytes.fromhex("849B57219DAE48DE646D07DBB533566E")

    msg = Encrypt0Message(plaintext, b'')
    cbor = msg.serialize(iv, key)
    print(cbor.hex())


if __name__ == '__main__':
    main()
