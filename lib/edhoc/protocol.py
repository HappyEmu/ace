import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ecdsa import SigningKey, VerifyingKey, NIST256p
from cbor2 import loads, dumps

from lib.cose.cose import SignatureVerificationFailed
from lib.edhoc.util import ecdh_cose_to_key, ecdh_key_to_cose
from lib.edhoc.messages import Message1, Message2, Message3, MessageOk, EDHOC_MSG_1, EDHOC_MSG_2, EDHOC_MSG_3
from lib.cose import Encrypt0Message, Signature1Message

backend = default_backend()


def derive_key(input_key: bytes, length: int, context_info: bytes):
    # length is in bytes
    hkdf = HKDF(algorithm=hashes.SHA256(),
                length=length,
                salt=None,
                info=context_info,
                backend=backend)

    return hkdf.derive(input_key)


def cose_kdf_context(algorithm_id: str, key_length: int, other: bytes):
    # key_length is in bytes
    return dumps([
        algorithm_id,
        [None, None, None], # PartyUInfo
        [None, None, None], # PartyVInfo
        [key_length, b'', other] # SuppPubInfo
    ])


def message_digest(message: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=backend)
    digest.update(message)
    return digest.finalize()


def transfer(src, dest, args):
    pass


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
        self.message3 = None

        self.oscore_master_secret = None
        self.oscore_master_salt = None

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
        iv_2 = derive_key(ecdh_shared_secret, 7, context_info=cose_kdf_context("IV-Generation", 7, other=aad2))

        msg2.encrypt(key=k_2, iv=iv_2)

        print("Server AAD2 =", aad2.hex())
        print("Server K2 =", k_2.hex())
        print("Server IV2 =", iv_2.hex())

        self.message2 = msg2.serialize()
        return msg2

    def on_msg_3(self, message):
        self.message3 = message
        (tag, p_sess_id, enc_3) = loads(message)

        msg3 = Message3(p_sess_id)
        aad3 = msg3.aad_3(message_digest, self.message1, self.message2)

        k_3 = derive_key(self.session.shared_secret, 16,
                         context_info=cose_kdf_context("AES-CCM-64-64-128", 16, other=aad3))
        iv_3 = derive_key(self.session.shared_secret, 7,
                          context_info=cose_kdf_context("IV-Generation", 7, other=aad3))

        sig_u = Encrypt0Message.decrypt(enc_3, k_3, iv_3, external_aad=aad3)

        payload = Signature1Message.verify(sig_u, self.client_id, external_aad=aad3)

        return MessageOk()

    def print_oscore_context(self):
        (master_secret, master_salt) = self._calculate_oscore_context()

        print("OSCORE MASTER SECRET CLIENT: ", master_secret.hex())
        print("OSCORE MASTER SALT CLIENT: ", master_salt.hex())

    def _calculate_oscore_context(self):
        if self.oscore_master_secret is not None and self.oscore_master_secret is not None:
            return self.oscore_master_secret, self.oscore_master_salt

        exchange_hash = message_digest(message_digest(self.message1 + self.message2) + self.message3)

        oscore_master_secret = derive_key(self.session.shared_secret, length=128 // 8,
                                          context_info=cose_kdf_context("EDHOC OSCORE Master Secret", 128 // 8,
                                                                        other=exchange_hash))
        oscore_master_salt = derive_key(self.session.shared_secret, length=56 // 8,
                                        context_info=cose_kdf_context("EDHOC OSCORE Master Salt", 56 // 8,
                                                                      other=exchange_hash))

        self.oscore_master_secret = oscore_master_secret
        self.oscore_master_salt = oscore_master_salt

        return oscore_master_secret, oscore_master_salt

    def encrypt(self, payload: bytes):
        secret, salt = self._calculate_oscore_context()

        return Encrypt0Message(payload).serialize(iv=salt, key=secret)


class Client:
    def __init__(self, sk: SigningKey, server_id: VerifyingKey):
        self.sk = sk
        self.vk = sk.get_verifying_key()
        self.server_id = server_id

        self.session = EdhocSession(session_id=None, shared_secret=None)
        self.message1 = None
        self.message2 = None
        self.message3 = None

        self.oscore_master_secret = None
        self.oscore_master_salt = None

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
        p_eph_key = ecdh_cose_to_key(p_eph_key)
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
                          context_info=cose_kdf_context("IV-Generation", 7, other=aad2))

        print("Client AAD2 =", aad2.hex())
        print("Client K2 =", k_2.hex())
        print("Client IV2 =", iv_2.hex())

        sig_v = Encrypt0Message.decrypt(enc_2, key=k_2, iv=iv_2, external_aad=aad2)

        payload = Signature1Message.verify(sig_v, self.server_id, external_aad=aad2)

        # Compute MSG3
        msg3 = Message3(peer_session_id=p_sess_id)
        aad3 = msg3.aad_3(message_digest, self.message1, self.message2)

        msg3.sign(self.sk, aad=aad3)

        k_3 = derive_key(ecdh_shared_secret,
                         length=16,
                         context_info=cose_kdf_context("AES-CCM-64-64-128", 16, other=aad3))
        iv_3 = derive_key(ecdh_shared_secret,
                          length=7,
                          context_info=cose_kdf_context("IV-Generation", 7, other=aad3))

        msg3.encrypt(k_3, iv_3)

        print("Client AAD3 =", msg3._aad_3.hex())
        print("Client K3 =", k_3.hex())
        print("Client IV3 =", iv_3.hex())

        self.message3 = msg3.serialize()
        (_, response) = send(msg3)

        print(response)

        return

    def encrypt(self, payload: bytes):
        secret, salt = self._calculate_oscore_context()

        return Encrypt0Message(payload).serialize(iv=salt, key=secret)

    def decrypt(self, ciphertext: bytes):
        secret, salt = self._calculate_oscore_context()

        return Encrypt0Message.decrypt(ciphertext, key=secret, iv=salt, external_aad=b'')

    def print_oscore_context(self):
        (master_secret, master_salt) = self._calculate_oscore_context()

        print("OSCORE MASTER SECRET CLIENT: ", master_secret.hex())
        print("OSCORE MASTER SALT CLIENT: ", master_salt.hex())

    def _calculate_oscore_context(self):
        if self.oscore_master_secret is not None and self.oscore_master_secret is not None:
            return self.oscore_master_secret, self.oscore_master_salt

        exchange_hash = message_digest(message_digest(self.message1 + self.message2) + self.message3)

        oscore_master_secret = derive_key(self.session.shared_secret, length=128 // 8,
                                          context_info=cose_kdf_context("EDHOC OSCORE Master Secret", 128 // 8,
                                                                        other=exchange_hash))
        oscore_master_salt = derive_key(self.session.shared_secret, length=56 // 8,
                                        context_info=cose_kdf_context("EDHOC OSCORE Master Salt", 56 // 8,
                                                                      other=exchange_hash))

        self.oscore_master_secret = oscore_master_secret
        self.oscore_master_salt = oscore_master_salt

        return oscore_master_secret, oscore_master_salt


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

    client.print_oscore_context()
    server.print_oscore_context()

    print("Done")


if __name__ == '__main__':
    main()
