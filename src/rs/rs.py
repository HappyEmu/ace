import random
import requests

from aiohttp import web
from cbor2 import dumps, loads
from ecdsa import VerifyingKey

import lib.cwt as cwt
from lib.cbor.constants import Keys as CK
from lib.cose.constants import Key as Cose
from lib.cose.cose import SignatureVerificationFailed
from lib.cose import CoseKey
from lib.http_server import HttpServer
from token_cache import TokenCache

AS_PUBLIC_KEY = VerifyingKey.from_der(bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200045aeec31f9e6"
                                                    "4aad45aba2d365e71e84dee0da331badab9118a2531501fd9861d027c9977ca32"
                                                    "d544e6342676ef00fa434b3aaed99f4823750517ca3390374753"))

AS_URL = 'http://localhost:8080'


class AudienceMismatchError(Exception):
    pass


class IntrospectionFailedError(Exception):
    pass


class IntrospectNotActiveError(Exception):
    pass


class ResourceServer(HttpServer):

    def __init__(self, audience, client_id=None, client_secret=None):
        self.audience = audience
        self.client_secret = client_secret
        self.client_id = client_id
        self.token_cache = TokenCache()

    def on_start(self, router):
        router.add_get('/temperature', self.get_temperature)
        router.add_get('/audience', self.get_audience)
        router.add_post('/authz-info', self.authz_info)

    # GET /temperature
    async def get_temperature(self, request):
        token = self.token_cache.get_token()

        # Verify scope
        if token[CK.SCOPE] != 'read_temperature':
            return web.Response(status=401, body=dumps({'error': 'not authorized'}))

        # TODO: Use OSCORE to encrypt and authenticate with PoP key in token

        temperature = random.randint(8, 42)
        return web.Response(status=200, body=dumps({'temperature': f"{temperature}C"}))

    async def get_audience(self, request):
        return self.audience

    # POST /authz_info
    async def authz_info(self, request):
        # Extract access token
        access_token = await request.content.read()

        # introspect_payload = self.introspect(access_token)

        # Verify if valid CWT from AS
        try:
            decoded = cwt.decode(access_token, key=AS_PUBLIC_KEY)

        except SignatureVerificationFailed as err:
            return web.Response(status=401, body=dumps({'error': str(err)}))

        # Check if audience claim in token matches audience identifier of this resource server
        if decoded[CK.AUD] != self.audience:
            return web.Response(status=403, body=dumps({'error': 'Audience mismatch'}))

        # Extract PoP Key
        pop_key = CoseKey.from_cose(decoded[CK.CNF][Cose.COSE_KEY])

        self.token_cache.add_token(token=decoded, pop_key=pop_key)

        return web.Response(status=204)

    def introspect(self, token: str):
        """
        POST token to AS for introspection using RS as a client of the AS
        :param token: The token to be introspected (not self-contained)
        """

        request = {
            CK.TOKEN: token,
            CK.TOKEN_TYPE_HINT: 'pop',
            CK.CLIENT_ID: self.client_id,
            CK.CLIENT_SECRET: self.client_secret
        }

        response = requests.post(f"{AS_URL}/introspect", data=dumps(request))
        response_payload = loads(response.content)
        """ ACE p. 61
        Response-Payload:
        {
            "active" : true,
            "aud" : "lockOfDoor4711",
            "scope" : "open, close",
            "iat" : 1311280970,
            "cnf" : {
                "kid" : b64’JDLUhTMjU2IiwiY3R5Ijoi ...’
            }
        }
        """

        if response.status_code != 201:
            raise IntrospectionFailedError()

        if not response_payload[CK.ACTIVE]:
            raise IntrospectNotActiveError()

        if response_payload[CK.AUD] != self.audience:
            raise AudienceMismatchError()

        return response_payload


if __name__ == '__main__':
    server = ResourceServer(audience="tempSensor0")
    server.start(port=8081)
