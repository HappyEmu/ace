import random
from threading import Thread

import jwt
from aiohttp import web
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode

from lib.token_cache import TokenCache

AS_CRYPTO_KEY = '123456789'
AS_SIGNATURE_KEY = '723984572'


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
        params = await request.json()

        cti = params['cti']

        token = self.token_cache.get_token(cti)

        # Verify scope
        if token['scope'] != 'read_temperature':
            return web.json_response(data={'error': 'not authorized'}, status=401)

        return web.json_response(data={'temperature': f"{self.temperature}C"}, status=205)

    async def get_audience(self, request):
        return self.audience

    async def authz_info(self, request):
        params = await request.json()

        # Extract access token
        access_token = params['access_token']

        # Verify JWT, verify token signature and audience
        try:
            decoded = jwt.decode(access_token,
                                 AS_SIGNATURE_KEY,
                                 algorithms=['HS256'],
                                 audience=self.audience)

        except (jwt.DecodeError, jwt.InvalidAudienceError) as err:
            return web.json_response(data={'error': str(err)}, status=401)

        # Extract PoP Key
        pop_key = jwk.JWK()
        pop_key.import_key(**decoded['cnf']['jwk'])

        # Verify nonce (not necessary)
        nonce = jws.JWS()
        nonce.deserialize(json_encode(params['nonce']))

        try:
            nonce.verify(pop_key, alg='ES256')
        except jws.InvalidJWSSignature as err:
            return str(err)

        # TODO: Check if client is allowed (check scope)

        cti = self.token_cache.add_token(decoded)

        return web.json_response(data={'cti': cti}, status=201)

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
    # threads = []
    #
    # for i in range(0, 1):
    #     thread = Thread(target=create_server, args=(i,))
    #     threads.append(thread)
    #     thread.start()
    #
    # for thread in threads:
    #     thread.join()
