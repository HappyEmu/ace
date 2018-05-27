import requests
import os

from ecdsa import SigningKey, VerifyingKey, NIST256p
from cbor2 import dumps, loads
from lib.cbor.constants import Keys as CK, GrantTypes
from lib.cose.constants import Key as Cose
from lib.cose import CoseKey

from lib.edhoc import Client as EdhocClient

AS_URL = 'http://localhost:8080'
#RS_URL = 'http://192.168.0.59:8000'
RS_URL = 'http://localhost:8081'


class AceSession:

    session_id = 0

    def __init__(self, session_id, private_key, public_key, key_id: bytes):
        self.session_id = session_id
        self.private_key = private_key
        self.public_key = public_key
        self.key_id = key_id
        self.token = None
        self.rs_public_key = None

    def bind_token(self, token: str):
        """
        Bind access token to this session
        :param token: The access token returned from the Authorization Server
        """

        self.token = token

    def bind_rs_public_key(self, public_key: VerifyingKey):
        self.rs_public_key = public_key

    @classmethod
    def create(cls):
        (key_id, prv_key, pub_key) = AceSession.generate_session_key()

        session_id = AceSession.session_id
        AceSession.session_id += 1

        return AceSession(session_id=session_id,
                          private_key=prv_key,
                          public_key=pub_key,
                          key_id=key_id)

    @staticmethod
    def generate_session_key():
        """
        Generates an asymmetric session key
        :return: (private_key, public_key) pair
        """

        key_id = os.urandom(2)

        private_key = SigningKey.generate(curve=NIST256p)
        public_key = private_key.get_verifying_key()

        return key_id, private_key, public_key


class Client:

    def __init__(self, client_id: str, client_secret: bytes):
        self.client_id = client_id
        self.client_secret = client_secret
        self.session = None

        self.start_new_session()

    def start_new_session(self):
        """
        Start a new ACE session
        """

        self.session = AceSession.create()

    def request_access_token(self, url):
        """
        Request access token from authorization server
        :param url: The URL of the authorization server
        """

        pop_key = self.session.public_key

        payload = {
            CK.GRANT_TYPE:    GrantTypes.CLIENT_CREDENTIALS,
            CK.CLIENT_ID:     self.client_id,
            CK.CLIENT_SECRET: self.client_secret,
            CK.SCOPE:         'read_temperature',
            CK.AUD:           'tempSensor0',
            CK.CNF:           { Cose.COSE_KEY: CoseKey(pop_key, self.session.key_id, CoseKey.Type.ECDSA).encode() }
        }

        response = requests.post(url=f"{url}/token", data=dumps(payload))

        if response.status_code != 200:
            print(f"\t ERROR: {loads(response.content)}")
            exit(1)

        response_content = loads(response.content)

        token = response_content[CK.ACCESS_TOKEN]
        rs_pub_key = CoseKey.from_cose(response_content[CK.RS_CNF])

        self.session.bind_token(token)
        self.session.bind_rs_public_key(rs_pub_key.key)

    def upload_access_token(self, url):
        """
        Upload access token to resource server to establish security context
        :param url: The url of the resource server
        """

        response = requests.post(url + '/authz-info', data=self.session.token)

        if response.status_code != 201:
            print(f"\t ERROR: {loads(response.content)}")
            exit(1)

    def establish_secure_context(self):
        def send(message):
            sent = message.serialize()

            received = requests.post(f'{RS_URL}/.well-known/edhoc', data=sent)

            return sent, received.content

        edhoc_client = EdhocClient(self.session.private_key, self.session.rs_public_key, on_send=send)
        edhoc_client.establish_context()

        print(edhoc_client.oscore_context)

        return edhoc_client

    def access_resource(self, edhoc_client, url):
        """
        Access protected resource
        :param edhoc_client: The EDHOC client to use
        :param url: The URL to the protected resource
        :return: Response from the protected resource
        """
        response = requests.get(url)

        if response.status_code != 200:
            print(f"\t ERROR: {loads(response.content)}")
            exit(1)

        decrypted_response = edhoc_client.decrypt(response.content)

        return loads(decrypted_response)

    def post_resource(self, edhoc_client, url, data: bytes):
        # Encrypt payload
        payload = edhoc_client.encrypt(data)

        response = requests.post(url, payload)

        if response.status_code != 204:
            print(f"\t ERROR: {loads(response.content)}")
            exit(1)

        #decrypted_response = edhoc_client.decrypt(response.content)

        #return loads(decrypted_response)
