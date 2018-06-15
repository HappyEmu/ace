import unittest
import hashlib
from ecdsa import SigningKey, NIST256p, NIST384p
from lib.edhoc import Client, Server, OscoreContext, bxor
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

        client_ctx = client.establish_context()
        server_ctx = server.oscore_context_for_recipient(client_ctx.sender_id)

        assert (client_ctx.master_secret == server_ctx.master_secret)
        assert (client_ctx.master_salt == server_ctx.master_salt)

    def test_multiple_clients(self):
        # Create server
        server_key = SigningKey.generate(curve=NIST256p)
        server_id = server_key.get_verifying_key()
        server = Server(server_key)

        # Bypass any network, simply invoke receive callback on server
        def test_send(message):
            sent = message.serialize()
            received = server.on_receive(sent).serialize()

            return sent, received

        # 1st Client
        client1_key = SigningKey.generate(curve=NIST256p)
        client1_id = client1_key.get_verifying_key()

        client1 = Client(client1_key,
                         server_id,
                         kid=b'client-1-id',
                         on_send=test_send)

        # 2nd Client
        client2_key = SigningKey.generate(curve=NIST256p)
        client2_id = client2_key.get_verifying_key()

        client2 = Client(client2_key,
                         server_id,
                         kid=b'client-2-id',
                         on_send=test_send)

        # Let server know about clients (simulate Uploading of Access Tokens)
        server.add_peer_identity(client1.kid, client1_id)
        server.add_peer_identity(client2.kid, client2_id)

        client1_context = client1.establish_context()
        client2_context = client2.establish_context()

        server_context_1 = server.oscore_context_for_recipient(client1_context.sender_id)
        server_context_2 = server.oscore_context_for_recipient(client2_context.sender_id)

        assert (client1_context.master_secret == server_context_1.master_secret)
        assert (client1_context.master_salt == server_context_1.master_salt)

        assert (client2_context.master_secret == server_context_2.master_secret)
        assert (client2_context.master_salt == server_context_2.master_salt)

        msg1 = b'Server to Client 1'
        msg2 = b'Server to Client 2'

        assert (client1_context.decrypt(server_context_1.encrypt(msg1)) == msg1)
        assert (client2_context.decrypt(server_context_2.encrypt(msg2)) == msg2)

    def test_oscore_context(self):
        ctx = OscoreContext(secret=bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
                            salt=bytes.fromhex("9e7ca92223786340"),
                            sid=b'',
                            rid=bytes.fromhex("01"))

        assert (ctx.sender_key() == bytes.fromhex("7230aab3b549d94c9224aacc744e93ab"))
        assert (ctx.recipient_key() == bytes.fromhex("e534a26a64aa3982e988e31f1e401e65"))
        # assert (ctx.common_iv() == bytes.fromhex("01727733ab49ead385b18f7d91"))

    def test_xor(self):
        a = bytes.fromhex("1234")
        b = bytes.fromhex("5678")

        assert (bxor(a, b) == bytes.fromhex("444C"))


if __name__ == '__main__':
    unittest.main()
