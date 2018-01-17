from aiohttp import web
from jwcrypto import jwk
from jwcrypto.common import json_decode
import jwt
import time

from cbor2 import dumps, loads
from lib.cbor.constants import Keys as CborKeys

from client_registry import ClientRegistry
from key_registry import KeyRegistry

class HttpServer:
    def __init__(self, port: int):
        self.port = port

    def start(self):
        app = web.Application()
        self.on_start(app.router)

        web.run_app(app, port=self.port)

    def on_start(self, router):
        pass


class AuthorizationServer(HttpServer):

    def __init__(self, crypto_key: str, signature_key: str):
        super().__init__(port=8080)

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

        client_id = params[CborKeys.CLIENT_ID]
        client_secret = params[CborKeys.CLIENT_SECRET]

        # Check if client is registered
        if not self.verify_client(client_id, client_secret):
            return web.Response(status=400, body=dumps({'error': 'unauthorized_client'}))

        # Extract Clients Public key
        client_pk = jwk.JWK()
        client_pk.import_key(**params[CborKeys.CNF]['jwk'])

        # Extract client claims scope and audience
        client_claims = {k: params[k] for k in (CborKeys.SCOPE, CborKeys.AUD)}

        # Create access token, bind PoP key
        token = self._bind_token(client_claims, client_pk)

        # Register bound PoP key for later reference
        self.key_registry.add_key(client_id, client_pk)

        response = {CborKeys.ACCESS_TOKEN: token.decode('ascii'),
                    CborKeys.TOKEN_TYPE: 'pop',
                    CborKeys.PROFILE: 'coap_oscore'}

        return web.Response(status=200, body=dumps(response))

    def _bind_token(self, client_claims: dict, session_key: jwk.JWK) -> bytes:
        """
        Bind session_key to access_token
        :param client_claims: client claims to be included in the access token
        :param session_key: PoP key to be bound to the access token
        :return:
        """
        # Bind session key to token
        claims = {CborKeys.ISS: 'ace.as-server.com',
                  CborKeys.IAT: int(time.time()),
                  CborKeys.EXP: int(time.time() + 7200.0),
                  CborKeys.CNF: {'jwk': json_decode(session_key.export())}}

        # Add client claims (aud and scope)
        claims.update(client_claims)

        # Create signed JWT
        token = jwt.encode(claims, self.signature_key, algorithm='HS256')

        return token

    def _verify_token_request(self, request_data: dict) -> bool:
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

    # POST
    async def introspect(self, request):
        params = loads(request.content.read())

        # Check if token was supplied
        if not CborKeys.TOKEN in params
            return web.Response(status=400, body=dumps({'error': 'missing "token" parameter'}))

        token = params[CborKeys.TOKEN] # required
        token_type_hint = params[CborKeys.TOKEN_TYPE_HINT] # optional

        # TODO: Retrieve context from token
        # client_id = ...
        #

        response = {
            'active': True,
            'scope': 'read',
            'cnf': {
                'COSE_KEY': {

                }
            }
        }

        return web.Response(status=201, body=dumps({}))




def main():
    server = AuthorizationServer(crypto_key='123456789',
                                 signature_key='723984572')
    server.start()


if __name__ == "__main__":
    main()
