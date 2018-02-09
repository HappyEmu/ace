from abc import ABCMeta, abstractmethod

import cbor2 as c

from lib.cose import Signature1Message, Encrypt0Message
from lib.edhoc.util import key_to_cose, cose_to_key

EDHOC_MSG_1 = 1
EDHOC_MSG_2 = 2
EDHOC_MSG_3 = 3


class EdhocMessage(metaclass=ABCMeta):

    _tag = None

    @property
    def tag(self):
        return self._tag

    @property
    @abstractmethod
    def content(self):
        pass

    def serialize(self):
        return c.dumps(self.content)


class Message1(EdhocMessage):

    _tag = EDHOC_MSG_1

    def __init__(self, session_id: bytes, nonce: bytes, ephemeral_key):
        self.session_id = session_id
        self.nonce = nonce
        self.ephemeral_key = ephemeral_key

    @property
    def content(self):
        return [self.tag, self.session_id, self.nonce, key_to_cose(self.ephemeral_key)]

    @classmethod
    def deserialize(cls, encoded: bytes):
        (tag, session_id, nonce, cose_key) = c.loads(encoded)

        if tag != EDHOC_MSG_1:
            raise ValueError("Not a MSG1 type")

        return Message1(session_id=session_id,
                        nonce=nonce,
                        ephemeral_key=cose_to_key(cose_key))


class Message2(EdhocMessage):

    _tag = EDHOC_MSG_2

    def __init__(self, session_id: bytes, peer_session_id: bytes, peer_nonce: bytes, peer_ephemeral_key):
        self.session_id = session_id
        self.peer_session_id = peer_session_id
        self.peer_nonce = peer_nonce
        self.peer_key = peer_ephemeral_key

        self._aad_2 = None
        self._cose_sig_v = None
        self._cose_enc_2 = None

    def sign(self, key, hashfunc, message_1):
        self._aad_2 = self.aad_2(hashfunc, message_1)
        self._cose_sig_v = self.cose_sig_v(key)

    def encrypt(self, key, iv):
        self._cose_enc_2 = self.cose_enc_2(key, iv)
        pass

    @property
    def content(self):
        return [*self.data_2, self._cose_enc_2]

    @property
    def data_2(self):
        return [self.tag, self.session_id, self.peer_session_id, self.peer_nonce, key_to_cose(self.peer_key)]

    def aad_2(self, hashfunc, message_1: bytes):
        return hashfunc(message_1 + c.dumps(self.data_2))

    def cose_enc_2(self, key, iv):
        return Encrypt0Message(plaintext=self._cose_sig_v, external_aad=self._aad_2).serialize(iv, key)

    def cose_sig_v(self, key):
        return Signature1Message(payload=b'', external_aad=self._aad_2).serialize_signed(key)

    @classmethod
    def deserialize(cls, encoded: bytes):
        (tag, session_id, peer_session_id, peer_nonce, cose_key, cose_enc_2) = c.loads(encoded)

        if tag != EDHOC_MSG_2:
            raise ValueError("Not a MSG2 type")

        return Message2(session_id=session_id,
                        peer_session_id=peer_session_id,
                        peer_nonce=peer_nonce,
                        peer_ephemeral_key=cose_key)


class Message3(EdhocMessage):
    _tag = EDHOC_MSG_3

    def __init__(self, peer_session_id):
        self.peer_session_id = peer_session_id

        self._aad_3 = None
        self._cose_sig_u = None
        self._cose_enc_3 = None

    def sign(self):
        pass

    def encrypt(self):
        pass

    @property
    def content(self):
        return [*self.data_3, self._cose_enc_3]

    @property
    def data_3(self):
        return [self.tag, self.peer_session_id]

    def aad_3(self):
        pass

    def cose_enc_3(self):
        pass

    def cose_sig_u(self):
        pass