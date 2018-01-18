from aiohttp import web
from jwcrypto import jwk
from jwcrypto.common import json_decode
import jwt
import time

from cbor2 import dumps, loads
from lib.cbor.constants import Keys as CK
from lib.http_server import HttpServer

from client_registry import ClientRegistry
from key_registry import KeyRegistry


class AuthorizationServer(HttpServer):

    def __init__(self, crypto_key: str, signature_key: str):
        self.crypto_key = crypto_key
        self.signature_key = signature_key
        self.client_registry = ClientRegistry()
        self.client_registry.register_client(client_id="ace_client_1", client_secret="ace_client_1_secret_123456")
        self.key_registry = KeyRegistry()

    def on_start(self, router):
        router.add_get('/clients', self.clients)
        router.add_post('/token', self.token)

    def verify_client(self, client_id, client_secret):
        return self.client_registry.check_secret(client_id, client_secret)

    async def clients(self, request):
        """
        Returns a list of all approved client IDs.
        DEBUG ONLY!
        """

        return web.json_response({'approved_clients': [c.client_id for c in self.client_registry.registered_clients]})

    # POST
    async def token(self, request):
        """
        Validates the incoming requests and grants an access token if valid. Must be POST [ACE 5.6.1]
        Returns error codes as stated in [ACE 5.6.3]
        """

        params = loads(await request.content.read())

        # Verify basic request
        if not self._verify_token_request(params):
            return web.Response(status=400, body=dumps({'error': 'invalid_request'}))

        client_id = params[CK.CLIENT_ID]
        client_secret = params[CK.CLIENT_SECRET]

        # Check if client is registered
        if not self.verify_client(client_id, client_secret):
            return web.Response(status=400, body=dumps({'error': 'unauthorized_client'}))

        # Extract Clients Public key
        client_pk = jwk.JWK()
        client_pk.import_key(**params[CK.CNF]['jwk'])

        # Extract client claims scope and audience
        client_claims = {k: params[k] for k in (CK.SCOPE, CK.AUD)}

        # Create access token, bind PoP key
        token = self._bind_token(client_claims, client_pk)

        # Register bound PoP key for later reference
        self.key_registry.add_key(client_id, client_pk)

        response = {CK.ACCESS_TOKEN: token.decode('ascii'),
                    CK.TOKEN_TYPE: 'pop',
                    CK.PROFILE: 'coap_oscore'}

        return web.Response(status=200, body=dumps(response))

    def _bind_token(self, client_claims: dict, session_key: jwk.JWK) -> bytes:
        """
        Bind session_key to access_token
        :param client_claims: client claims to be included in the access token
        :param session_key: PoP key to be bound to the access token
        :return:
        """
        # Bind session key to token
        claims = {CK.ISS: 'ace.as-server.com',
                  CK.IAT: int(time.time()),
                  CK.EXP: int(time.time() + 7200.0),
                  CK.CNF: {'jwk': json_decode(session_key.export())}}

        # Add client claims (aud and scope)
        claims.update(client_claims)

        # Create signed JWT
        token = jwt.encode(payload=claims, key=self.signature_key, algorithm='HS256')

        return token

    def _verify_token_request(self, request_data: dict) -> bool:
        """
        Verify that the incoming request data conform to the standard
        :param request_data: incoming data as CBOR Map
        :return: True if request payload is valid, False otherwise
        """
        expected_keys = [CK.GRANT_TYPE,
                         CK.CLIENT_ID,
                         CK.CLIENT_SECRET,
                         CK.AUD]

        if request_data is None:
            return False

        return all(key in request_data for key in expected_keys)

    # POST
    async def introspect(self, request):
        params = loads(request.content.read())

        # Check if token was supplied
        if CK.TOKEN not in params:
            return web.Response(status=400, body=dumps({'error': 'missing "token" parameter'}))

        token = params[CK.TOKEN]  # required
        token_type_hint = params[CK.TOKEN_TYPE_HINT]  # optional

        # TODO: Retrieve context (PoP) from token and retrieve authorization information from 'DB'
        # client_id = ...
        # pop_key = ...

        response = {
            CK.ACTIVE: True,
            CK.SCOPE: 'read_temperature',
            CK.AUD: '...',
            CK.ISS: '...',
            CK.EXP: '...',
            CK.IAT: '...',
            CK.CNF: {
                'COSE_KEY': {}
            }
        }

        return web.Response(status=201, body=dumps(response))


def main():
    server = AuthorizationServer(crypto_key='123456789',
                                 signature_key='723984572')
    server.start()


if __name__ == "__main__":
    main()
