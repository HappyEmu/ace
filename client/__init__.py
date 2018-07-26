import requests

from typing import List
from cbor2 import dumps, loads
from lib.cbor.constants import Keys as CK, GrantTypes
from lib.cose.constants import Key as Cose
from lib.cose import CoseKey
from lib.edhoc import Client as EdhocClient

from .ace_session import AceSession


class Client:

    def __init__(self, client_id: str, client_secret: bytes):
        self.client_id = client_id
        self.client_secret = client_secret
        self.sessions = {}

    def request_access_token(self, as_url: str, audience: str, scopes: List['str']):
        """
        Request access token from authorization server
        :param as_url: The URL of the authorization server
        :param audience: The audience of the resource server
        :param scopes: The scopes to be accessed
        """
        session = AceSession.create(key_id=bytes(f"{self.client_id}{AceSession.session_id}", 'ascii'))

        pop_key = session.public_pop_key

        payload = {
            CK.GRANT_TYPE:    GrantTypes.CLIENT_CREDENTIALS,
            CK.CLIENT_ID:     self.client_id,
            CK.CLIENT_SECRET: self.client_secret,
            CK.SCOPE:         ",".join(scopes),
            CK.AUD:           audience,
            CK.CNF:           { Cose.COSE_KEY: CoseKey(pop_key, session.pop_key_id, CoseKey.Type.ECDSA).encode() }
        }

        response = requests.post(url=f"{as_url}/token", data=dumps(payload))

        if response.status_code != 200:
            print(f"\t ERROR: {loads(response.content)}")
            exit(1)

        response_content = loads(response.content)

        token = response_content[CK.ACCESS_TOKEN]
        rs_pub_key = CoseKey.from_cose(response_content[CK.RS_CNF])

        session.token = token
        session.rs_public_key = rs_pub_key.key

        return session

    def upload_access_token(self, session: AceSession, rs_url: str, endpoint: str):
        """
        Upload access token to resource server to establish security context
        :param session The ACE session to use
        :param rs_url: The url of the resource server
        :param endpoint: The Authz-Info endpoint path
        """

        response = requests.post(rs_url + endpoint, data=session.token)

        if response.status_code != 201:
            print(f"\t ERROR: {loads(response.content)}")
            exit(1)

        session.rs_url = rs_url

    def establish_secure_context(self, session: AceSession):
        def send(message):
            sent = message.serialize()

            received = requests.post(f'{session.rs_url}/.well-known/edhoc', data=sent)

            return sent, received.content

        edhoc_client = EdhocClient(session.private_pop_key,
                                   session.rs_public_key,
                                   kid=bytes(self.client_id, 'ascii'),
                                   on_send=send)
        oscore_context = edhoc_client.establish_context()

        print(oscore_context)

        return oscore_context

    def access_resource(self, session: AceSession, url: str):
        """
        Access protected resource
        :param url: The URL to the protected resource
        :param session: The ACE session to use
        :return: Response from the protected resource
        """
        session.ensure_oscore_context()

        data = session.oscore_context.encrypt(b'')
        response = requests.get(url, data=data)

        if response.status_code != 200:
            print(f"\t ERROR: {loads(response.content)}")
            exit(1)

        decrypted_response = session.oscore_context.decrypt(response.content)

        return loads(decrypted_response)

    def post_resource(self, session: AceSession, url: str, data: bytes):
        session.ensure_oscore_context()

        # Encrypt payload
        payload = session.oscore_context.encrypt(data)

        response = requests.post(url, payload)

        if response.status_code != 201:
            print(f"\t ERROR: {loads(response.content)}")
            exit(1)

        decrypted_response = session.oscore_context.decrypt(response.content)

        return loads(decrypted_response)
