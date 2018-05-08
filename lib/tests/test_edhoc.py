import unittest
import hashlib
from ecdsa import SigningKey, NIST256p, NIST384p
from lib.edhoc.util import ecdsa_key_to_cose, ecdsa_cose_to_key


class TestEdhoc(unittest.TestCase):
    def test_signature(self):
        sk = SigningKey.generate(curve=NIST384p)
        vk = sk.get_verifying_key()

        encoded = ecdsa_key_to_cose(vk)

        data = b"this is some data I'd like to sign"
        signature = sk.sign(data, hashfunc=hashlib.sha256)

        decoded = ecdsa_cose_to_key(encoded)
        decoded.verify(signature, data, hashfunc=hashlib.sha256)

        print(signature)
        assert(decoded.verify(signature, data, hashfunc=hashlib.sha256))


if __name__ == '__main__':
    unittest.main()
