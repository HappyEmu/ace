from lib.coap.server import CoapServer
from cbor2 import dumps, loads

import aiocoap.resource as resource
import aiocoap


class AuthzInfoResource(resource.Resource):

    def render_post(self, request):
        params = loads(request.payload)

        return aiocoap.Message(payload=b'OK')


class ResourceServerCoap(CoapServer):
    server_name = 'resource-server'

    def on_start(self, site):
        site.add_resource(('authz_info',), AuthzInfoResource())


if __name__ == '__main__':
    ResourceServerCoap().start()
