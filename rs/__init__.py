import random

from .resource_server import ResourceServer

from aiohttp import web
from cbor2 import dumps, loads
from ecdsa import VerifyingKey, SigningKey

from lib.edhoc import OscoreContext
from .token_cache import TokenCache


class TemperatureServer(ResourceServer):

    def __init__(self,
                 audience: str,
                 identity: SigningKey,
                 as_url: str,
                 as_public_key: VerifyingKey,
                 client_id=None,
                 client_secret=None):
        super().__init__(audience, identity, as_url, as_public_key, client_id, client_secret)

    def on_start(self, router):
        super().on_start(router)

        router.add_get('/temperature', self.wrap("read_temperature", self.get_temperature))
        router.add_post('/led', self.wrap("post_led", self.post_led))

    def post_led(self, request, payload, token: dict, oscore_context: OscoreContext):
        data = loads(oscore_context.decrypt(payload))

        print(f"Setting LED value to: {data[b'led_value']}")

        response = oscore_context.encrypt(dumps(b'OK'))
        return web.Response(status=201, body=response)

    # GET /temperature
    def get_temperature(self, request, payload, token: dict, oscore_context: OscoreContext):
        temperature = random.randint(8, 42)
        response = oscore_context.encrypt(dumps({'temperature': f"{temperature}C"}))

        return web.Response(status=200, body=response)
