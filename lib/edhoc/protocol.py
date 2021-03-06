import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ecdsa import SigningKey, VerifyingKey, NIST256p
from cbor2 import loads, dumps

from lib.cose.cose import SignatureVerificationFailed
from lib.edhoc.context import OscoreContext
from lib.edhoc.util import ecdh_cose_to_key, ecdh_key_to_cose
from lib.edhoc.messages import Message1, Message2, Message3, MessageOk, \
    MessageError, EDHOC_MSG_1, EDHOC_MSG_2, EDHOC_MSG_3, EdhocMessage
from lib.cose import Encrypt0Message, Signature1Message
from lib.cose.constants import Header, Algorithm

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


class EdhocSession:

    def __init__(self):
        self.id: bytes = None
        self.peer_id: bytes = None
        self.shared_secret: bytes = None
        self.private_key = None
        self.peer_public_key = None

        self.message1: bytes = None
        self.message2: bytes = None
        self.message3: bytes = None

        self._oscore_context: OscoreContext = None

    @property
    def oscore_context(self):
        if self._oscore_context is None:
            exchange_hash = message_digest(message_digest(self.message1 + self.message2) + self.message3)

            key_size = 128 // 8
            salt_size = 64 // 8

            master_secret = derive_key(
                self.shared_secret,
                length=key_size,
                context_info=cose_kdf_context("EDHOC OSCORE Master Secret", key_size, other=exchange_hash)
            )

            master_salt = derive_key(
                self.shared_secret,
                length=salt_size,
                context_info=cose_kdf_context("EDHOC OSCORE Master Salt", salt_size, other=exchange_hash)
            )

            self._oscore_context = OscoreContext(
                secret=master_secret,
                salt=master_salt,
                sid=self.id,
                rid=self.peer_id
            )

        return self._oscore_context


class Server:
    def __init__(self, sk: SigningKey):
        self.sk: SigningKey = sk
        self.vk: VerifyingKey = sk.get_verifying_key()
        self.peer_identities = {}
        self.sessions = []
        self.security_contexts = {}
        self.pop_key_by_rid = {}

        super().__init__()

    def add_peer_identity(self, key_id: bytes, key: VerifyingKey):
        self.peer_identities[key_id] = key

    def on_receive(self, message):
        print("Server Received: ", message.hex())

        decoded = loads(message)

        if decoded[0] == EDHOC_MSG_1:
            session = EdhocSession()
            self.sessions.append(session)
            return self.on_msg_1(message, session)
        elif decoded[0] == EDHOC_MSG_3:
            session_id = decoded[1]
            session = [s for s in self.sessions if s.id == session_id][0]
            return self.on_msg_3(message, session)

    def on_msg_1(self, message: bytes, session: EdhocSession):
        session.message1 = message
        msg = Message1.deserialize(message)

        session_id = os.urandom(2)
        nonce = os.urandom(8)

        session_key = ec.generate_private_key(ec.SECP256R1, backend)
        public_session_key = session_key.public_key()

        peer_session_key = msg.ephemeral_key
        peer_session_id = msg.session_id

        ecdh_shared_secret = session_key.exchange(ec.ECDH(), peer_session_key)

        session.id = session_id
        session.peer_id = peer_session_id
        session.private_key = session_key
        session.public_key = public_session_key
        session.shared_secret = ecdh_shared_secret

        msg2 = Message2(session_id=peer_session_id,
                        peer_session_id=session_id,
                        peer_nonce=nonce,
                        peer_ephemeral_key=public_session_key)

        aad2 = msg2.aad_2(message_digest, session.message1)

        # Sign message
        msg2.sign(self.sk, aad=aad2)

        # Encrypt message
        k_2 = derive_key(ecdh_shared_secret, 16, context_info=cose_kdf_context("AES-CCM-64-64-128", 16, other=aad2))
        iv_2 = derive_key(ecdh_shared_secret, 13, context_info=cose_kdf_context("IV-Generation", 13, other=aad2))

        msg2.encrypt(key=k_2, iv=iv_2)

        #print("Server AAD2 =", aad2.hex())
        #print("Server K2 =", k_2.hex())
        #print("Server IV2 =", iv_2.hex())

        session.message2 = msg2.serialize()
        return msg2

    def on_msg_3(self, message: bytes, session: EdhocSession):
        session.message3 = message
        (tag, p_sess_id, enc_3) = loads(message)

        msg3 = Message3(p_sess_id)
        aad3 = msg3.aad_3(message_digest, session.message1, session.message2)

        k_3 = derive_key(session.shared_secret, 16,
                         context_info=cose_kdf_context("AES-CCM-64-64-128", 16, other=aad3))
        iv_3 = derive_key(session.shared_secret, 13,
                          context_info=cose_kdf_context("IV-Generation", 13, other=aad3))

        sig_u = Encrypt0Message.decrypt(enc_3, k_3, iv_3, external_aad=aad3)

        # Retrieve public key using kid
        pop_key_id = loads(loads(sig_u).value[1])[Header.KID]

        # Perform proof-of-possession
        try:
            pop_key = self.peer_identities[pop_key_id]
            payload = Signature1Message.verify(sig_u, pop_key, external_aad=aad3)

            self.security_contexts[session.peer_id] = session.oscore_context
            self.pop_key_by_rid[session.peer_id] = pop_key_id
        except (SignatureVerificationFailed, KeyError) as e:
            return MessageError()

        return MessageOk()

    def oscore_context_for_recipient(self, rid: bytes):
        return self.security_contexts[rid]

    def pop_key_id_for_recipient(self, rid: bytes):
        return self.pop_key_by_rid[rid]


class Client:
    def __init__(self, sk: SigningKey, server_id: VerifyingKey, kid: bytes, on_send):
        self.sk = sk
        self.vk = sk.get_verifying_key()
        self.server_id = server_id
        self.kid = kid
        self.on_send = on_send
        self.session = EdhocSession()

        super().__init__()

    def establish_context(self):
        self._initiate_edhoc()
        return self._continue_edhoc()

    def _initiate_edhoc(self):
        session_id = os.urandom(2)
        nonce = os.urandom(8)

        session_key = ec.generate_private_key(ec.SECP256R1, backend)
        public_session_key = session_key.public_key()

        self.session.id = session_id
        self.session.private_key = session_key
        self.session.public_key = public_session_key

        msg1 = Message1(session_id, nonce, public_session_key)

        (sent, response) = self.on_send(msg1)

        self.session.message1 = sent
        self.session.message2 = response

    def _continue_edhoc(self):
        (tag, sess_id, p_sess_id, p_nonce, p_eph_key, enc_2) = loads(self.session.message2)

        # Compute EDHOC shared secret
        p_eph_key = ecdh_cose_to_key(p_eph_key)
        ecdh_shared_secret = self.session.private_key.exchange(ec.ECDH(), p_eph_key)
        self.session.shared_secret = ecdh_shared_secret
        self.session.peer_id = p_sess_id

        # Derive encryption key
        msg2 = Message2(sess_id, p_sess_id, p_nonce, p_eph_key)
        aad2 = msg2.aad_2(message_digest, self.session.message1)

        k_2 = derive_key(ecdh_shared_secret,
                         length=16,
                         context_info=cose_kdf_context("AES-CCM-64-64-128", 16, other=aad2))
        iv_2 = derive_key(ecdh_shared_secret,
                          length=13,
                          context_info=cose_kdf_context("IV-Generation", 13, other=aad2))

        #print("Client AAD2 =", aad2.hex())
        #print("Client K2 =", k_2.hex())
        #print("Client IV2 =", iv_2.hex())

        sig_v = Encrypt0Message.decrypt(enc_2, key=k_2, iv=iv_2, external_aad=aad2)

        payload = Signature1Message.verify(sig_v, self.server_id, external_aad=aad2)

        # Compute MSG3
        msg3 = Message3(peer_session_id=p_sess_id)
        aad3 = msg3.aad_3(message_digest, self.session.message1, self.session.message2)

        msg3.sign(self.sk, kid=self.kid, aad=aad3)

        k_3 = derive_key(ecdh_shared_secret,
                         length=16,
                         context_info=cose_kdf_context("AES-CCM-64-64-128", 16, other=aad3))
        iv_3 = derive_key(ecdh_shared_secret,
                          length=13,
                          context_info=cose_kdf_context("IV-Generation", 13, other=aad3))

        msg3.encrypt(k_3, iv_3)

        #print("Client AAD3 =", msg3._aad_3.hex())
        #print("Client K3 =", k_3.hex())
        #print("Client IV3 =", iv_3.hex())

        self.session.message3 = msg3.serialize()
        (_, response) = self.on_send(msg3)

        #print(response)

        return self.session.oscore_context
