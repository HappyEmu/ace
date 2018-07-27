import time
import os

from aiohttp import web
from cbor2 import dumps, loads
from ecdsa import VerifyingKey, SigningKey
from collections import namedtuple
from typing import Dict

from lib.cbor.constants import Keys as CK
from lib.cose.constants import Key as Cose
from lib.cose import CoseKey
from lib.http_server import HttpServer
from .client_registry import ClientRegistry, Client
from .key_registry import KeyRegistry
from .token_registry import TokenRegistry
from lib.ace.aus.access_token import AccessToken


class AuthorizationServer(HttpServer):

    def __init__(self, identity: SigningKey):
        self.identity = identity
        self.client_registry = ClientRegistry()
        self.key_registry = KeyRegistry()
        self.token_registry = TokenRegistry()
        self.resource_servers: Dict[str, ResourceServer] = {}

    def register_client(self, client_id, client_secret, grants):
        self.client_registry.register_client(Client(client_id, client_secret, grants))

    def register_resource_server(self, audience, scopes, public_key):
        self.resource_servers[audience] = ResourceServer(audience, scopes, public_key)

    def public_key(self):
        self.identity.get_verifying_key()

    def on_start(self, router):
        router.add_post('/token', self.token)
        router.add_post('/introspect', self.introspect)

    def verify_client(self, client_id, client_secret):
        return self.client_registry.check_secret(client_id, client_secret)

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

        # Check if audience exists
        requested_audience = params[CK.AUD]
        if requested_audience not in self.resource_servers.keys():
            return web.Response(status=400, body=dumps({'error': 'unknown_audience'}))

        # Retrieve Resource Server for Audience
        rs = self.resource_servers[requested_audience]

        # Check if RS has requested scopes
        requested_scopes = params[CK.SCOPE].split(",")
        if not all(elem in rs.scopes for elem in requested_scopes):
            return web.Response(status=400, body=dumps({'error': 'unknown_scope'}))

        # Check if client is allowed to access scopes on audience
        # TODO

        # Extract Clients Public PoP key
        client_pop_key = CoseKey.from_cose(params[CK.CNF][Cose.COSE_KEY])

        # Extract client claims scope and audience
        client_claims = {k: params[k] for k in (CK.SCOPE, CK.AUD)}

        # Create access token, bind PoP key
        token = self._bind_token(client_claims, client_pop_key)

        # Register bound PoP key for later reference
        self.key_registry.add_key(client_id, client_pop_key)
        self.token_registry.add_token(token, self_contained=True)

        token_sent = token.sign_and_export_self_contained(self.identity, key_id=b'ace.as-server.com')
        # token_sent = token.export_referential()

        response = {
            CK.ACCESS_TOKEN: token_sent,
            CK.TOKEN_TYPE: 'pop',
            CK.PROFILE: 'coap_oscore',
            CK.RS_CNF: CoseKey(rs.public_key, b'rs_pub_key', CoseKey.Type.ECDSA).encode()
        }

        return web.Response(status=200, body=dumps(response))

    def _bind_token(self, client_claims: dict, session_key: VerifyingKey) -> AccessToken:
        """
        Bind session_key to access_token
        :param client_claims: client claims to be included in the access token
        :param session_key: PoP key to be bound to the access token
        :return:
        """
        cti = os.urandom(2)

        # Claims to be included in the access token
        claims = {
            CK.ISS: 'ace.as-server.com',
            CK.IAT: int(time.time()),
            CK.EXP: int(time.time() + 7200.0),
            CK.CTI: cti.hex()  # TODO: use 'bytes' instead of string as per spec
        }

        # Add client claims (aud and scope)
        claims.update(client_claims)

        # Create Token and bind PoP key
        token = AccessToken(claims=claims)
        token.bind_key(session_key)

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
        params = loads(await request.content.read())

        # Check if token was supplied
        if CK.TOKEN not in params:
            return web.Response(status=400, body=dumps({'error': 'missing "token" parameter'}))

        token = params[CK.TOKEN]  # required
        token_type_hint = params[CK.TOKEN_TYPE_HINT]  # optional

        access_context = self.token_registry.get_token(reference=token)

        response = {
            CK.ACTIVE: True,
            CK.SCOPE: access_context.scope,
            CK.AUD: access_context.audience,
            CK.ISS: access_context.issuer,
            CK.EXP: access_context.expires,
            CK.IAT: access_context.issued_at,
            CK.CNF: {
                Cose.COSE_KEY: access_context.bound_key.encode()
            }
        }

        return web.Response(status=201, body=dumps(response))


ResourceServer = namedtuple('ResourceServer', 'audience scopes public_key')
Grant = namedtuple('Grant', 'audience scopes')
