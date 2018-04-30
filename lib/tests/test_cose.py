import unittest
from ecdsa import SigningKey, NIST256p
from lib import cwt
from lib.cose.constants import Header, Key, Algorithm
from lib.cose import Encrypt0Message
from lib.cbor.constants import Keys as CK
from lib.edhoc.util import ecdsa_key_to_cose
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

class TestCose(unittest.TestCase):
    def test_parse_token(self):
        key = SigningKey.generate(curve=NIST256p)
        pk = key.get_verifying_key()

        cose_key = ecdsa_key_to_cose(pk, kid=b'you-know-that-one')

        claims = {
            CK.AUD: 'thatSensor01',
            CK.SCOPE: 'r',
            CK.IAT: 234234,
            CK.CNF: { Key.COSE_KEY: cose_key }
        }

        token = cwt.encode(claims, key)
        print(token.hex())
        payload = cwt.decode(token, pk)
        print(payload)

    def test_parse_cose(self):
        plaintext = b"helloworld"

        iv = bytes.fromhex("89F52F65A1C580")
        key = bytes.fromhex("849B57219DAE48DE646D07DBB533566E")

        msg = Encrypt0Message(plaintext, b'')
        cbor = msg.serialize(iv, key)

        assert(cbor == bytes.fromhex("d08343a1010ca1054789f52f65a1c580522516dd4791d9839305afef86175e1de5d2fc"))

    def test_aes(self):
        key = bytes.fromhex("0544b756233b5f78a21d849aea2ccae2")
        salt = bytes.fromhex("4ff37bb4ff8b5169")
        ciphertext = bytes.fromhex("3462416fab63dea222c41ec699aa7c")
        aad = bytes.fromhex("8368456e63727970743043a1010c40")
        tag = bytes.fromhex("5649ef4c5d432152")

        aes = AESCCM(key, tag_length=8)
        cl_ciphertext = aes.encrypt(salt, bytes.fromhex("a16b74656d7065726174757265181e"), aad)

        plaintext = aes.decrypt(salt, ciphertext, aad)

        print(plaintext.hex())


if __name__ == '__main__':
    unittest.main()
