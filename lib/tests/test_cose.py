import unittest
from ecdsa import SigningKey, NIST256p
from lib.cose.constants import Header, Key, Algorithm
from lib.cose import Encrypt0Message, cwt
from lib.cbor.constants import Keys as CK
from lib.edhoc.util import ecdsa_key_to_cose
from cbor2 import dumps


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

        token = cwt.encode(claims, key, kid=b'')
        print(token.hex())
        payload = cwt.decode(token, pk)
        print(payload)

    def test_encrypt0(self):
        """ Test parameters from https://github.com/cose-wg/Examples/blob/master/RFC8152/Appendix_C_4_1.json"""
        plaintext = b"This is the content."

        iv = bytes.fromhex("89F52F65A1C580933B5261A78C")
        key = bytes.fromhex("849B5786457C1491BE3A76DCEA6C4271")

        prot = dumps({ Header.ALG: 10 }) # "alg":"AES-CCM-16-128/64"
        unprot = { Header.IV: iv }

        msg = Encrypt0Message(plaintext,
                              protected_header=prot,
                              unprotected_header=unprot,
                              external_aad=b'')
        cbor = msg.serialize(iv, key)

        assert(cbor == bytes.fromhex("D08343A1010AA1054D89F52F65A1C580933B5261A78C581C5974E1B99A3A4CC09A659AA2E9E7FFF161D38CE71CB45CE460FFB569"))


if __name__ == '__main__':
    unittest.main()
