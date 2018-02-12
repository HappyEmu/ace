from ecdsa import SigningKey, VerifyingKey, NIST384p, NIST256p
from cryptography.hazmat.primitives.asymmetric import ec
from lib.edhoc.message import Message1, Message2, EDHOC_MSG_1, EDHOC_MSG_3, Message3, MessageOk
from lib.edhoc.protocol import backend, message_digest, derive_key, cose_kdf_context
from lib.edhoc.util import cose_to_key
from lib.cose import Encrypt0Message, Signature1Message
from cbor2 import loads
import os


class EdhocSession:
    def __init__(self, session_id, shared_secret):
        self.id = session_id
        self.shared_secret = shared_secret
        self.private_key = None
        self.public_key = None


class Server:
    def __init__(self, sk: SigningKey, client_id: VerifyingKey):
        self.sk = sk
        self.vk = sk.get_verifying_key()
        self.client_id = client_id
        self.session = EdhocSession(session_id=None, shared_secret=None)

        self.message1 = None
        self.message2 = None

    def on_receive(self, message):
        print("Server Received: ", message.hex())

        decoded = loads(message)

        if decoded[0] == EDHOC_MSG_1:
            return self.on_msg_1(message)
        elif decoded[0] == EDHOC_MSG_3:
            return self.on_msg_3(message)

    def on_msg_1(self, message):
        self.message1 = message
        msg = Message1.deserialize(message)

        session_id = os.urandom(2)
        nonce = os.urandom(8)

        session_key = ec.generate_private_key(ec.SECP256R1, backend)
        public_session_key = session_key.public_key()

        peer_session_key = msg.ephemeral_key
        peer_session_id = msg.session_id

        ecdh_shared_secret = session_key.exchange(ec.ECDH(), peer_session_key)

        self.session.id = session_id
        self.session.private_key = session_key
        self.session.public_key = public_session_key
        self.session.shared_secret = ecdh_shared_secret

        msg2 = Message2(session_id=peer_session_id,
                        peer_session_id=session_id,
                        peer_nonce=nonce,
                        peer_ephemeral_key=public_session_key)

        aad2 = msg2.aad_2(message_digest, self.message1)

        # Sign message
        msg2.sign(self.sk, aad=aad2)

        # Encrypt message
        k_2 = derive_key(ecdh_shared_secret, 16, context_info=cose_kdf_context("AES-CCM-64-64-128", 16, other=aad2))
        iv_2 = derive_key(ecdh_shared_secret, 7, context_info=cose_kdf_context("IV-Generation", 16, other=aad2))

        msg2.encrypt(key=k_2, iv=iv_2)

        print("Server AAD2 =", aad2.hex())
        print("Server K2 =", k_2.hex())
        print("Server IV2 =", iv_2.hex())

        self.message2 = msg2.serialize()
        return msg2

    def on_msg_3(self, message):
        (tag, p_sess_id, enc_3) = loads(message)

        msg3 = Message3(p_sess_id)
        aad3 = msg3.aad_3(message_digest, self.message1, self.message2)

        k_3 = derive_key(self.session.shared_secret, 16,
                         context_info=cose_kdf_context("AES-CCM-64-64-128", 16, other=aad3))
        iv_3 = derive_key(self.session.shared_secret, 7,
                          context_info=cose_kdf_context("IV-Generation", 16, other=aad3))

        sig_u = Encrypt0Message.decrypt(enc_3, k_3, iv_3, external_aad=aad3)

        valid = Signature1Message.verify(sig_u, self.client_id, external_aad=aad3)

        return MessageOk()


class Client:
    def __init__(self, sk: SigningKey, server_id: VerifyingKey):
        self.sk = sk
        self.vk = sk.get_verifying_key()
        self.server_id = server_id

        self.session = EdhocSession(session_id=None, shared_secret=None)
        self.message1 = None
        self.message2 = None

    def initiate_edhoc(self, send):
        session_id = os.urandom(2)
        nonce = os.urandom(8)

        session_key = ec.generate_private_key(ec.SECP256R1, backend)
        public_session_key = session_key.public_key()

        self.session.id = session_id
        self.session.private_key = session_key
        self.session.public_key = public_session_key

        msg1 = Message1(session_id, nonce, public_session_key)

        (sent, response) = send(msg1)

        self.message1 = sent
        self.message2 = response

    def continue_edhoc(self, send):
        (tag, sess_id, p_sess_id, p_nonce, p_eph_key, enc_2) = loads(self.message2)

        # Compute EDHOC shared secret
        p_eph_key = cose_to_key(p_eph_key)
        ecdh_shared_secret = self.session.private_key.exchange(ec.ECDH(), p_eph_key)
        self.session.shared_secret = ecdh_shared_secret

        # Derive encryption key
        msg2 = Message2(sess_id, p_sess_id, p_nonce, p_eph_key)
        aad2 = msg2.aad_2(message_digest, self.message1)

        k_2 = derive_key(ecdh_shared_secret,
                         length=16,
                         context_info=cose_kdf_context("AES-CCM-64-64-128", 16, other=aad2))
        iv_2 = derive_key(ecdh_shared_secret,
                          length=7,
                          context_info=cose_kdf_context("IV-Generation", 16, other=aad2))

        print("Client AAD2 =", aad2.hex())
        print("Client K2 =", k_2.hex())
        print("Client IV2 =", iv_2.hex())

        sig_v = Encrypt0Message.decrypt(enc_2, key=k_2, iv=iv_2, external_aad=aad2)

        valid = Signature1Message.verify(sig_v, self.server_id, external_aad=aad2)

        assert valid

        # Compute MSG3
        msg3 = Message3(peer_session_id=p_sess_id)
        aad3 = msg3.aad_3(message_digest, self.message1, self.message2)

        msg3.sign(self.sk, aad=aad3)

        k_3 = derive_key(ecdh_shared_secret,
                         length=16,
                         context_info=cose_kdf_context("AES-CCM-64-64-128", 16, other=aad3))
        iv_3 = derive_key(ecdh_shared_secret,
                          length=7,
                          context_info=cose_kdf_context("IV-Generation", 16, other=aad3))

        msg3.encrypt(k_3, iv_3)

        print("Client AAD3 =", msg3._aad_3.hex())
        print("Client K3 =", k_3.hex())
        print("Client IV3 =", iv_3.hex())

        (_, response) = send(msg3)

        print(response)

        return


def main():
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

    print("Done")


if __name__ == '__main__':
    main()
