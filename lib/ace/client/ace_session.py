import requests

from ecdsa import SigningKey, VerifyingKey, NIST256p
from lib.edhoc import Client as EdhocClient


class AceSession:

    session_id = 0

    def __init__(self, session_id, private_pop_key, public_pop_key, pop_key_id: bytes):
        self.session_id = session_id
        self.private_pop_key = private_pop_key
        self.public_pop_key = public_pop_key
        self.pop_key_id = pop_key_id
        self.token = None
        self.rs_url = None
        self.rs_public_key = None
        self.oscore_context = None

    def ensure_oscore_context(self, rs_url: str):
        if self.oscore_context is None:
            self.establish_oscore_context(rs_url)

    def establish_oscore_context(self, rs_url: str):
        if self.oscore_context is not None:
            return

        def send(message):
            sent = message.serialize()

            received = requests.post(f'{rs_url}/.well-known/edhoc', data=sent)

            return sent, received.content

        edhoc_client = EdhocClient(self.private_pop_key,
                                   self.rs_public_key,
                                   kid=self.pop_key_id,
                                   on_send=send)

        oscore_context = edhoc_client.establish_context()

        print(oscore_context)

        self.oscore_context = oscore_context

    @classmethod
    def create(cls, key_id: bytes):
        (prv_key, pub_key) = AceSession.generate_session_key()

        session_id = AceSession.session_id
        AceSession.session_id += 1

        return AceSession(session_id=session_id,
                          private_pop_key=prv_key,
                          public_pop_key=pub_key,
                          pop_key_id=key_id)

    @staticmethod
    def generate_session_key():
        """
        Generates an asymmetric session key
        :return: (private_key, public_key) pair
        """

        private_key = SigningKey.generate(curve=NIST256p)
        public_key = private_key.get_verifying_key()

        return private_key, public_key
