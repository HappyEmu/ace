import logging

import asyncio

import aiocoap.resource as resource
import aiocoap
from cbor2 import dumps, loads


class TokenResource(resource.Resource):

    def __init__(self):
        super().__init__()

    async def render_post(self, request):
        params = loads(request.payload)

        return aiocoap.Message(payload=b'OK')


class CoapServer:

    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        logging.getLogger("coap-server").setLevel(logging.DEBUG)

    def start(self):
        # Resource tree creation
        root = resource.Site()
        self.on_start(root)

        asyncio.Task(aiocoap.Context.create_server_context(root))
        asyncio.get_event_loop().run_forever()

    def on_start(self, site):
        pass


class AuthorizationServer(CoapServer):

    def on_start(self, site):
        site.add_resource(('token',), TokenResource())


def main():
    AuthorizationServer().start()


if __name__ == "__main__":
    main()
