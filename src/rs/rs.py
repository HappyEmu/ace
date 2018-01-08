import random
from threading import Thread

import jwt
from flask import Flask, jsonify, request
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
        self.app.run(port=self.port)

    def get_temperature(self):
        params = request.get_json()

        cti = params['cti']

        token = self.token_cache.get_token(cti)

        # Verify scope
        if token['scope'] != 'read_temperature':
            return jsonify({'error': 'not authorized'}), 401

        return jsonify({'temperature': f"{self.temperature}C"}), 205

    def get_audience(self):
        return self.audience

    def authz_info(self):
        params = request.get_json()

        # Extract access token
        access_token = params['access_token']

        # Verify JWT, verify token signature and audience
        try:
            decoded = jwt.decode(access_token,
                                 AS_SIGNATURE_KEY,
                                 algorithms=['HS256'],
                                 audience=self.audience)

        except (jwt.DecodeError, jwt.InvalidAudienceError) as err:
            return jsonify({'error': str(err)}), 401

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

        return jsonify({'cti': cti}), 201

    def __create_app__(self):
        app = Flask(__name__)

        app.add_url_rule('/temperature', 'temperature', self.get_temperature)
        app.add_url_rule('/audience', 'audience', self.get_audience)
        app.add_url_rule('/authz-info', 'authz-info', self.authz_info, methods=['POST'])

        return app


# Creates and starts a server
def create_server(num):
    server = ResourceServer(port=8081 + num, audience=f"tempSensor{num}")
    server.start()


if __name__ == '__main__':
    threads = []

    for i in range(0, 1):
        thread = Thread(target=create_server, args=(i,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
