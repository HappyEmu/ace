import unittest
import hashlib
from ecdsa import SigningKey, NIST256p, NIST384p
from lib.edhoc import Client, Server
from lib.edhoc.util import ecdsa_key_to_cose, ecdsa_cose_to_key


class TestEdhoc(unittest.TestCase):
    def test_signature(self):
        sk = SigningKey.generate(curve=NIST384p)
        vk = sk.get_verifying_key()

        encoded = ecdsa_key_to_cose(vk)

        data = b"this is some data I'd like to sign"
        signature = sk.sign(data, hashfunc=hashlib.sha256)

        decoded = ecdsa_cose_to_key(encoded)
        assert(decoded.verify(signature, data, hashfunc=hashlib.sha256))

    def test_context(self):
        client_sk = SigningKey.generate(curve=NIST256p)
        server_sk = SigningKey.generate(curve=NIST256p)

        client_id = client_sk.get_verifying_key()
        server_id = server_sk.get_verifying_key()

        client = Client(client_sk, server_id)
        server = Server(server_sk, client_id)

        def send(message):
            sent = message.serialize()
            received = server.on_receive(sent).serialize()

            return sent, received

        client.initiate_edhoc(send)
        client.continue_edhoc(send)

        client_ctx = client.oscore_context
        server_ctx = server.oscore_context
        assert(client_ctx == server_ctx)


if __name__ == '__main__':
    unittest.main()
