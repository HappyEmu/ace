import datetime
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


class Server:

    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        logging.getLogger("coap-server").setLevel(logging.DEBUG)

    def start(self):
        # Resource tree creation
        root = resource.Site()
        root.add_resource(('token',), TokenResource())

        asyncio.Task(aiocoap.Context.create_server_context(root))
        asyncio.get_event_loop().run_forever()


def main():
    Server().start()


if __name__ == "__main__":
    main()
