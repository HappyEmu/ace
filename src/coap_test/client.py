import logging
import asyncio

from aiocoap import *
from jwcrypto import jwk, jws
from jwcrypto.common import json_decode
from lib.cbor.constants import Keys as CborKeys, GrantTypes
from cbor2 import dumps, loads

logging.basicConfig(level=logging.INFO)


class Client:

    def __init__(self, id, secret):
        self.id = id
        self.secret = secret
        self.protocol = None

    @classmethod
    async def create(cls, id, secret):
        self = Client(id, secret)
        self.protocol = await Context.create_client_context()
        return self

    async def request_token(self):
        private_key, public_key = self._generate_session_key()

        request_params = {CborKeys.GRANT_TYPE: GrantTypes.CLIENT_CREDENTIALS,
                          CborKeys.CLIENT_ID: self.id,
                          CborKeys.CLIENT_SECRET: self.secret,
                          CborKeys.SCOPE: 'read_temperature',
                          CborKeys.AUD: 'tempSensor0',
                          CborKeys.CNF: {'jwk': json_decode(public_key.export())}}

        request = Message(code=Code.POST,
                          uri='coap://localhost/token',
                          payload=dumps(request_params))

        try:
            response = await self.protocol.request(request).response
        except Exception as e:
            print('Failed to fetch resource:')
            print(e)
        else:
            print('Result: %s\n%r' % (response.code, response.payload))

    def _generate_session_key(self):
        """
        Generates an asymmetric session key
        :return: (private_key, public_key) pair
        """
        private_key = jwk.JWK.generate(kty='EC', size=160)
        public_key = jwk.JWK()
        public_key.import_key(**json_decode(private_key.export_public()))

        return private_key, public_key


async def main():
    client = await Client.create(id='123456789',
                                 secret='verysecret')

    await client.request_token()


if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
