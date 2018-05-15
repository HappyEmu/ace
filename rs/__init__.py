import random
import requests

from aiohttp import web
from cbor2 import dumps, loads
from ecdsa import VerifyingKey, SigningKey, NIST256p

import lib.cwt as cwt
from lib.cbor.constants import Keys as CK
from lib.cose.constants import Key as Cose
from lib.cose.cose import SignatureVerificationFailed
from lib.cose import CoseKey
from lib.edhoc import Server as EdhocServer
from lib.http_server import HttpServer
from .token_cache import TokenCache

AS_PUBLIC_KEY = VerifyingKey.from_der(bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200047069be"
                                                    "d49cab8ffa5b1c820271aef0bc0c8f5cd149e05c5b9e37686da06d02bd5f"
                                                    "7bc35ea8265be7c5e276ad7e7d0eb05e4a0551102a66bba88b02b5eb4c33"
                                                    "55"))

RS_PRIVATE_KEY = SigningKey.from_der(bytes.fromhex("307702010104200ffc411715d3cc4917bd27ac4f310552b085b1ca0bb0a8"
                                                   "bbb9d8931d651544c1a00a06082a8648ce3d030107a144034200046cc415"
                                                   "12d92fb03cb3b35bed5b494643a8a8a55503e87a90282c78d6c58a7e3c88"
                                                   "a21c0287e7e8d76b0052b1f1a2dcebfea57714c1210d42f17b335adcb76d"
                                                   "7a"))

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

        self.edhoc_server = None

    def on_start(self, router):
        router.add_get('/temperature', self.get_temperature)
        router.add_get('/audience', self.get_audience)
        router.add_post('/authz-info', self.authz_info)
        router.add_post('/.well-known/edhoc', self.edhoc)

    async def edhoc(self, request):
        message = await request.content.read()

        response = self.edhoc_server.on_receive(message)

        return web.Response(status=201, body=response.serialize())

    # GET /temperature
    async def get_temperature(self, request):
        token = self.token_cache.get_token()

        print(self.edhoc_server.oscore_context)

        # Verify scope
        if token[CK.SCOPE] != 'read_temperature':
            return web.Response(status=401, body=dumps({'error': 'not authorized'}))

        temperature = random.randint(8, 42)

        response = self.edhoc_server.encrypt(dumps({'temperature': f"{temperature}C"}))

        return web.Response(status=200, body=response)

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

        # Prepare Edhoc Server
        self.edhoc_server = EdhocServer(RS_PRIVATE_KEY, pop_key.key)

        return web.Response(status=201)

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


def main():
    server = ResourceServer(audience="tempSensor0")
    server.start(port=8081)


if __name__ == '__main__':
    main()
