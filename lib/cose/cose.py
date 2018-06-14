import hashlib

from cbor2 import loads, dumps, CBORTag
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from ecdsa import SigningKey, VerifyingKey, util

from lib.cose.constants import Header, Tag, Algorithm

signature_algorithms = ['ES256', 'ES384', 'ES521']


class SignatureVerificationFailed(Exception):
    pass


class Signature1Message:

    def __init__(self,
                 payload: bytes=b'',
                 external_aad: bytes=b'',
                 protected_header: bytes=None,
                 unprotected_header: bytes=None):

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

        print("Signature is: ", signature.hex())

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

        signature = key.sign_deterministic(to_sign, hashlib.sha256, sigencode=util.sigencode_string)

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

        if not key.verify(signature, to_verify, hashlib.sha256, sigdecode=util.sigdecode_string):
            raise SignatureVerificationFailed()

        return payload


class Encrypt0Message:

    def __init__(self,
                 plaintext: bytes,
                 protected_header: bytes,
                 unprotected_header: dict,
                 external_aad: bytes = b''):
        self.plaintext = plaintext
        self.unprotected_header = unprotected_header
        self.protected_header = protected_header
        self.external_aad = external_aad

    def serialize(self, iv: bytes, key: bytes):
        enc_structure = Encrypt0Message.enc_structure(self.protected_header, self.external_aad)
        aad = dumps(enc_structure)

        ciphertext = self._encrypt(key, iv, aad=aad)

        cose_encrypt0 = [self.protected_header, self.unprotected_header, ciphertext]

        return dumps(CBORTag(Tag.COSE_ENCRYPT0, cose_encrypt0))

    # AES-CCM-64-64-128 = AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce
    def _encrypt(self, key: bytes, iv: bytes, aad: bytes):
        cipher = AESCCM(key, tag_length=8)
        ciphertext = cipher.encrypt(nonce=iv, data=self.plaintext, associated_data=aad)

        return ciphertext

    @classmethod
    def enc_structure(cls, protected: bytes, external_aad: bytes):
        return ["Encrypt0", protected, external_aad]

    @classmethod
    def decrypt(cls, encoded: bytes, key: bytes, iv: bytes, external_aad: bytes):
        decoded = loads(encoded)

        tag = decoded.tag
        (protected, unprotected, ciphertext) = decoded.value

        aad = dumps(Encrypt0Message.enc_structure(protected, external_aad))

        print("OSCORE AAD: ", aad.hex())
        print("TAG: ", ciphertext[-8:].hex())

        cipher = AESCCM(key, tag_length=8)
        plaintext = cipher.decrypt(nonce=iv, data=ciphertext, associated_data=aad)

        return plaintext
