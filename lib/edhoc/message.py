from abc import ABCMeta, abstractmethod
from functools import reduce

import cbor2 as c
from ecdsa import VerifyingKey

from lib.cose import signature1_message

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
        ary = [[self.tag], self.content]
        flattened = reduce(lambda x, y: x+y, ary)
        return c.dumps(flattened)


class Message1(EdhocMessage):

    _tag = EDHOC_MSG_1

    def __init__(self, session_id: bytes, nonce: bytes, key: VerifyingKey):
        self.session_id = session_id
        self.nonce = nonce
        self.key = key

    @property
    def content(self):
        return [self.session_id, self.nonce, self.key.to_der()]

    @classmethod
    def deserialize(cls, encoded: bytes):
        (tag, session_id, nonce, key) = c.loads(encoded)

        if tag != EDHOC_MSG_1:
            raise ValueError("Not a MSG1 type")

        return Message1(session_id=session_id, nonce=nonce, key=VerifyingKey.from_der(key))


class Message2(EdhocMessage):

    _tag = EDHOC_MSG_2

    def __init__(self, partner_session_id: bytes, session_id: bytes, nonce: bytes, key: VerifyingKey):
        self.partner_session_id = partner_session_id
        self.session_id = session_id
        self.nonce = nonce
        self.key = key

    @property
    def content(self):
        return [self.data_2, self.cose_enc_2]

    def data_2(self):
        return [self._tag, self.partner_session_id, self.session_id, self.nonce, self.key.to_der()]

    def cose_enc_2(self):
        pass

    def aad_2(self, hashfunc, message_1: bytes):
        return hashfunc(message_1 + c.dumps(self.data_2()))

    def cose_sig_v(self):
        return signature1_message(payload=None, key=self)


