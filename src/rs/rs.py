import random

import jwt
from aiohttp import web
from jwcrypto import jwk, jws
from cbor2 import dumps, loads
from lib.cbor.constants import Keys as CborKeys

from token_cache import TokenCache

AS_CRYPTO_KEY = '123456789'
AS_SIGNATURE_KEY = '723984572'


class AudienceMismatchError(Exception):
    def __init__(self):
        self.message = "RS audience did not match token audience"


def json_to_cbor(json: dict) -> dict:
    return { int(k): json[k] for k in json.keys() }


class ResourceServer(object):

    def __init__(self, port, audience):
        self.audience = audience
        self.port = port
        self.app = self.__create_app__()
        self.temperature = random.randint(8, 42)
        self.token_cache = TokenCache()

    def start(self):
        web.run_app(self.app, port=self.port)

    async def get_temperature(self, request):
        params = await request.content.read()

        cti = params['cti']

        token = self.token_cache.get_token(cti)

        # Verify scope
        if token[str(CborKeys.SCOPE)] != 'read_temperature':
            return web.json_response(data={'error': 'not authorized'}, status=401)

        return web.json_response(data={'temperature': f"{self.temperature}C"}, status=205)

    async def get_audience(self, request):
        return self.audience

    async def authz_info(self, request):
        # Extract access token
        access_token = loads(await request.content.read())

        # Verify JWT, verify token signature and audience
        try:
            decoded = json_to_cbor(jwt.decode(access_token,
                                              AS_SIGNATURE_KEY,
                                              algorithms=['HS256'],
                                              audience=None))

            # Check if audience claim in token matches audience identifier of this resource server
            if decoded[CborKeys.AUD] != self.audience:
                raise AudienceMismatchError()

        except (jwt.DecodeError,
                jwt.InvalidAudienceError,
                jwt.MissingRequiredClaimError,
                AudienceMismatchError) as err:
            return web.Response(status=401, body=dumps({'error': str(err)}))

        # Extract PoP Key
        pop_key = jwk.JWK()
        pop_key.import_key(**decoded[CborKeys.CNF]['jwk'])
        # str(...) temporarily necessary because JSON does not allow integer keys

        cti = self.token_cache.add_token(decoded, pop_key=pop_key)

        return web.Response(status=201, body=dumps({CborKeys.CTI: cti}))

    def __create_app__(self):
        app = web.Application()

        app.router.add_get('/temperature', self.get_temperature)
        app.router.add_get('/audience', self.get_audience)
        app.router.add_post('/authz-info', self.authz_info)

        return app


# Creates and starts a server
def create_server(num):
    server = ResourceServer(port=8081 + num, audience=f"tempSensor{num}")
    server.start()


if __name__ == '__main__':
    create_server(0)
