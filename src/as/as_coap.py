import time
from aiocoap import *
import aiocoap.resource as resource
from cbor2 import dumps, loads
from jwcrypto import jwk
from jwcrypto.common import json_decode
import jwt

from lib.cbor.constants import Keys as CborKeys
from lib.coap.server import CoapServer
from client_registry import ClientRegistry


class TokenResource(resource.Resource):

    def __init__(self, server):
        super().__init__()
        self.server = server

    async def render_post(self, request):
        params = loads(request.payload)

        # Verify basic request
        if not self._verify_token_request(params):
            return Message(code=Code.BAD_REQUEST,
                           payload=dumps({'error': 'invalid_request'}))

        client_id = params[CborKeys.CLIENT_ID]
        client_secret = params[CborKeys.CLIENT_SECRET]

        # Check if client is registered
        if not self.server.verify_client(client_id, client_secret):
            return Message(code=Code.UNAUTHORIZED, payload=dumps({'error': 'unauthorized_client'}))

        # Extract Clients Public key
        client_pk = jwk.JWK()
        client_pk.import_key(**params[CborKeys.CNF]['jwk'])

        # Extract client claims scope and audience
        client_claims = {k: params[k] for k in (CborKeys.SCOPE, CborKeys.AUD)}

        # Issue Token
        token = self.server.bind_token(client_claims, client_pk)

        return Message(code=Code.CONTENT,
                       payload=dumps({'access_token': token.decode('utf-8'),
                                      'token_type': 'pop',
                                      'csp': 'coap_dtls'}))

    def _verify_token_request(self, request_data: dict):
        """
        Verify that the incoming request data conform to the standard
        :param request_data: incoming data as CBOR Map
        :return: True if request payload is valid, False otherwise
        """
        expected_keys = [CborKeys.GRANT_TYPE,
                         CborKeys.CLIENT_ID,
                         CborKeys.CLIENT_SECRET,
                         CborKeys.AUD]

        if request_data is None:
            return False

        return all(key in request_data for key in expected_keys)


class AuthorizationServer(CoapServer):
    server_name = 'authorization-server'

    def __init__(self, crypto_key: str, signature_key: str):
        super().__init__()
        self.crypto_key = crypto_key
        self.signature_key = signature_key
        self.client_registry = ClientRegistry()
        self.client_registry.register_client(client_id="123456789", client_secret="verysecret")

    def on_start(self, site: resource.Site):
        site.add_resource(('token',), TokenResource(self))

    def verify_client(self, client_id: str, client_secret: str):
        return self.client_registry.check_secret(client_id, client_secret)

    def bind_token(self, client_claims: dict, session_key: jwk.JWK):
        # Bind session key to token
        claims = {CborKeys.ISS: 'ace.as-server.com',
                  CborKeys.IAT: int(time.time()),
                  CborKeys.CNF: {'jwk': json_decode(session_key.export())}}

        # Add client claims (aud and scope)
        claims.update(client_claims)

        # Create signed JWT
        token = jwt.encode(claims, self.signature_key, algorithm='HS256')

        return token


def main():
    AuthorizationServer(crypto_key='123456789',
                        signature_key='723984572').start()


if __name__ == "__main__":
    main()
