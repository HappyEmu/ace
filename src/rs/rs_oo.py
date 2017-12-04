import random
from threading import Thread

import jwt
from flask import Flask, jsonify, request
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode

AS_CRYPTO_KEY = '123456789'
AS_SIGNATURE_KEY = '723984572'


class ResourceServer(object):

    def __init__(self, port, audience):
        self.audience = audience
        self.port = port
        self.app = self.__create_app__()
        self.temperature = random.randint(8, 42)

    def start(self):
        self.app.run(port=self.port)

    def get_temperature(self):
        return jsonify({'temperature': f"{self.temperature}C"})

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
            return str(err), 401

        # Extract PoP Key
        pop_key = jwk.JWK()
        pop_key.import_key(**decoded['cnf']['jwk'])

        # Verify nonce
        nonce = jws.JWS()
        nonce.deserialize(json_encode(params['nonce']))

        try:
            nonce.verify(pop_key, alg='ES256')
        except jws.InvalidJWSSignature as err:
            return str(err)

        # TODO: Check if client is allowed (check scope)

        return "OK"

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
