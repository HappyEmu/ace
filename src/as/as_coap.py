import aiocoap.resource as resource
import aiocoap
from cbor2 import dumps, loads
from lib.coap.server import CoapServer


class TokenResource(resource.Resource):

    def __init__(self):
        super().__init__()

    async def render_post(self, request):
        params = loads(request.payload)

        return aiocoap.Message(payload=b'OK')


class AuthorizationServer(CoapServer):
    server_name = 'authorization-server'

    def on_start(self, site):
        site.add_resource(('token',), TokenResource())


def main():
    AuthorizationServer().start()


if __name__ == "__main__":
    main()
