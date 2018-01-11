import binascii
import os
import asyncio

import requests
from aiocoap import *
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


async def main():
    # Generate Asymmetric Session Key
    private_key, public_key = generate_session_key()

    protocol = await Context.create_client_context()

    # Request access token from AS
    cbor_token_request = { CborKeys.GRANT_TYPE:    GrantTypes.CLIENT_CREDENTIALS,
                           CborKeys.CLIENT_ID:     CLIENT_ID,
                           CborKeys.CLIENT_SECRET: CLIENT_SECRET,
                           CborKeys.SCOPE:         'read_temperature',
                           CborKeys.AUD:           'tempSensor0',
                           CborKeys.CNF:           { 'jwk': json_decode(public_key.export())} }

    print(f"\n========== CLIENT TO AS ==========")
    print(f"\t ===> Sending {cbor_token_request} to /token at AS")

    request = Message(code=Code.GET, uri=f"coap://{AS_URL}/token", payload=dumps(cbor_token_request))

    response = await protocol.request(request).response

    print(f"\t <=== Received response {response.json()}")

    # Check Access Token
    if response.status_code == 200:
        token = response.json()['access_token']
    else:
        token = None

    if not token:
        print(f"\t ERROR: {response.json()}")
        exit(1)

    # TODO: Authenticate RS (using RS public key returned in 'rs_cnf' from AS)

    # Make Resource request, sign nonce
    signed_nonce = generate_signed_nonce(private_key)

    upload_token_request = {'access_token': token,
                            'nonce': signed_nonce}

    print(f"\n========== CLIENT TO RS ==========")
    print(f"\t ===> Sending {upload_token_request} to /authz-info at RS")

    response = requests.post(RS_URL + '/authz-info', json=upload_token_request)

    print(f"\t <=== Received {response.json()}")

    if response.status_code != 201:
        exit(1)

    # Get protected resource
    resource_request = {'cti': response.json()['cti']}

    print(f"\t ===> Sending {resource_request} to /authz-info at RS")

    response = requests.get(RS_URL + '/temperature', json=resource_request)

    print(f"\t <=== Received {response.json()}")


if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
