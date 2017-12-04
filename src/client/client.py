import binascii
import os

import requests
from jwcrypto import jwk, jws
from jwcrypto.common import json_decode

CLIENT_ID = '123456789'
CLIENT_SECRET = 'verysecret'

AS_URL = 'http://localhost:8080'
RS_URL = 'http://localhost:8081'


def main():
    # Generate Asymmetric Session Key
    private_key = jwk.JWK.generate(kty='EC', size=160)
    public_key = jwk.JWK()
    public_key.import_key(**json_decode(private_key.export_public()))

    # Request access token from AS
    token_request = {'grant_type': 'client_credentials',
                     'client_id': CLIENT_ID,
                     'client_secret': CLIENT_SECRET,
                     'scope': 'read',
                     'aud': 'tempSensor0',
                     'cnf': {'jwk': json_decode(public_key.export())}}

    response = requests.post(AS_URL + '/token', json=token_request)

    # Check Access Token
    if response.status_code == 200:
        token = response.json()['access_token']
    else:
        token = None

    if not token:
        print("Did not get token :( Exiting...")
        exit(1)

    # Make Resource request, sign nonce
    nonce = jws.JWS(binascii.hexlify(os.urandom(16)).decode('utf-8'))
    nonce.add_signature(private_key, alg='ES256')

    resource_request = {'access_token': token,
                        'nonce': json_decode(nonce.serialize())}

    response = requests.post(RS_URL + '/authz-info', json=resource_request)

    print(response.text)


if __name__ == '__main__':
    main()
