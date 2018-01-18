import random
import jwt
import requests

from aiohttp import web
from jwcrypto import jwk, jws
from cbor2 import dumps, loads
from lib.cbor.constants import Keys as CK
from lib.http_server import HttpServer

from token_cache import TokenCache

AS_CRYPTO_KEY = '123456789'
AS_SIGNATURE_KEY = '723984572'
AS_URL = 'http://localhost:8080'


class AudienceMismatchError(Exception): pass
class IntrospectionFailedError(Exception): pass
class IntrospectNotActiveError(Exception): pass


def json_to_cbor(json: dict) -> dict:
    """
    Convert string keys to integer keys
    """

    return { int(k): json[k] for k in json.keys() }


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
        if token[str(CK.SCOPE)] != 'read_temperature':
            return web.Response(status=401, body=dumps({'error': 'not authorized'}))

        # TODO: Use OSCORE to encrypt and authenticate with PoP key in token

        temperature = random.randint(8, 42)
        return web.Response(status=200, body=dumps({'temperature': f"{temperature}C"}))

    async def get_audience(self, request):
        return self.audience

    # POST /authz_info
    async def authz_info(self, request):
        # Extract access token
        access_token = loads(await request.content.read())

        # Verify JWT
        try:
            # Verify if valid JWT from AS
            decoded = json_to_cbor(jwt.decode(access_token,
                                              AS_SIGNATURE_KEY,
                                              algorithms=['HS256'],
                                              audience=None))
        except (jwt.DecodeError,
                jwt.InvalidAudienceError,
                jwt.MissingRequiredClaimError,) as err:
            return web.Response(status=401, body=dumps({'error': str(err)}))

        # Check if audience claim in token matches audience identifier of this resource server
        if decoded[CK.AUD] != self.audience:
            raise AudienceMismatchError()

        # Extract PoP Key
        pop_key = jwk.JWK(**decoded[CK.CNF]['jwk'])

        self.token_cache.add_token(token=decoded, pop_key=pop_key)

        return web.Response(status=204)

    def introspect(self, token: str):
        """
        POST token to AS for introspection using RS as a client of the AS
        :param token: The token to be introspected (not self-contained)
        """

        request = {
            CK.TOKEN: token,
            CK.CLIENT_ID: self.client_id,
            CK.CLIENT_SECRET: self.client_secret
        }

        response = requests.post(f"{AS_URL}/introspect")
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

        if response.status_code != 200:
            raise IntrospectionFailedError()

        if not response_payload[CK.ACTIVE]:
            raise IntrospectNotActiveError()

        if response_payload[CK.AUD] != self.audience:
            raise AudienceMismatchError()

        return response_payload


if __name__ == '__main__':
    server = ResourceServer(audience="tempSensor0")
    server.start(port=8081)
