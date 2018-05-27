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

        server = Server(server_sk)

        def send(message):
            sent = message.serialize()
            received = server.on_receive(sent).serialize()

            return sent, received

        client = Client(client_sk, server_id, kid=b'client-1234', on_send=send)
        server.add_peer_identity(client.kid, client_id)

        client.establish_context()

        client_ctx = client.oscore_context()
        server_ctx = server.sessions[0].oscore_context

        assert(client_ctx == server_ctx)

    def test_multiple_clients(self):
        server_key = SigningKey.generate(curve=NIST256p)
        server_id = server_key.get_verifying_key()
        server = Server(server_key)

        def test_send(message):
            sent = message.serialize()
            received = server.on_receive(sent).serialize()

            return sent, received

        # 1st Client
        client1_key = SigningKey.generate(curve=NIST256p)
        client1_id = client1_key.get_verifying_key()
        client1 = Client(client1_key, server_id, kid=b'client-1-id', on_send=test_send)

        # 2nd Client
        client2_key = SigningKey.generate(curve=NIST256p)
        client2_id = client2_key.get_verifying_key()
        client2 = Client(client2_key, server_id, kid=b'client-2-id', on_send=test_send)

        # Let server know about clients (simulate Uploading of Access Tokens)
        server.add_peer_identity(client1.kid, client1_id)
        server.add_peer_identity(client2.kid, client2_id)

        client1.establish_context()
        client2.establish_context()

        assert(client1.oscore_context() == server.sessions[0].oscore_context)
        assert(client2.oscore_context() == server.sessions[1].oscore_context)


if __name__ == '__main__':
    unittest.main()
