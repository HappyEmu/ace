import binascii
import os
import asyncio
import requests

from jwcrypto import jwk, jws
from jwcrypto.common import json_decode
from cbor2 import dumps, loads
from lib.cbor.constants import Keys as CborKeys, GrantTypes

CLIENT_ID = '123456789'
CLIENT_SECRET = 'verysecret'

AS_URL = 'http://localhost:8080'
RS_URL = 'http://localhost:8081'


def generate_session_key():
    """
    Generates an asymmetric session key
    :return: (private_key, public_key) pair
    """
    private_key = jwk.JWK.generate(kty='EC', size=160)
    public_key = jwk.JWK()
    public_key.import_key(**json_decode(private_key.export_public()))

    return private_key, public_key


def generate_signed_nonce(private_key):
    nonce = binascii.hexlify(os.urandom(16)).decode('utf-8')

    jws_nonce = jws.JWS(nonce)
    jws_nonce.add_signature(private_key, alg='ES256')

    return jws_nonce.serialize(compact=True)


def main():
    # Generate Asymmetric Session Key
    private_key, public_key = generate_session_key()

    # Request access token from AS
    cbor_token_request = { CborKeys.GRANT_TYPE:    GrantTypes.CLIENT_CREDENTIALS,
                           CborKeys.CLIENT_ID:     CLIENT_ID,
                           CborKeys.CLIENT_SECRET: CLIENT_SECRET,
                           CborKeys.SCOPE:         'read_temperature',
                           CborKeys.AUD:           'tempSensor0',
                           CborKeys.CNF:           { 'jwk': json_decode(public_key.export())} }

    print(f"\n========== CLIENT TO AS ==========")
    print(f"\t ===> Sending {cbor_token_request} to /token at AS")

    response = requests.post(url=f"{AS_URL}/token", data=dumps(cbor_token_request))

    print(f"\t <=== Received response {loads(response.content)}")

    # Check Access Token
    if response.status_code != 200:
        print(f"\t ERROR: {loads(response.content)}")
        exit(1)

    token = loads(response.content)[CborKeys.ACCESS_TOKEN]

    # TODO: Authenticate RS (using RS public key returned in 'rs_cnf' from AS)

    upload_token_request_payload = dumps(token)

    print(f"\n========== CLIENT TO RS ==========")
    print(f"\t ===> Uploading token to /authz-info at RS")

    response = requests.post(RS_URL + '/authz-info', data=upload_token_request_payload.decode('ascii'))

    print(f"\t <=== Received {response.content}")

    if response.status_code != 201:
        exit(1)

    # Get protected resource
    resource_request = {'cti': response.json()['cti']}

    print(f"\t ===> Sending {resource_request} to /authz-info at RS")

    response = requests.get(RS_URL + '/temperature', json=resource_request)

    print(f"\t <=== Received {response.json()}")


if __name__ == '__main__':
    main()
