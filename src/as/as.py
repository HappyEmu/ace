from access_token import Token
from client_registry import ClientRegistry
from aiohttp import web
from jwcrypto import jwk

from cbor2 import dumps, loads
from lib.cbor.constants import TokenRequest

CRYPTO_KEY = '123456789'
SIGNATURE_KEY = '723984572'


# Verifies that
def verify_token_request(request_data):
    expected_keys = [TokenRequest.GRANT_TYPE,
                     TokenRequest.CLIENT_ID,
                     TokenRequest.CLIENT_SECRET,
                     TokenRequest.AUD]

    if request_data is None:
        return False

    return all(key in request_data for key in expected_keys)


def verify_client(client_id, client_secret):
    return client_registry.check_secret(client_id, client_secret)


client_registry = ClientRegistry()
client_registry.register_client(client_id="123456789", client_secret="verysecret")


# Clients endpoint
#
# Returns a list of all approved client IDs.
# ONLY FOR DEBUGGING PURPOSES
async def clients(request):
    return web.json_response({'approved_clients': [c.client_id for c in client_registry.registered_clients]})


# Token endpoint
#
# Validates the incoming requests and grants an access token if valid. Must be POST [ACE 5.6.1]
# Returns error codes as stated in [ACE 5.6.3]
async def token(request):
    params = loads(await request.content.read())

    # Verify basic request
    if not verify_token_request(params):
        return web.json_response(data={'error': 'invalid_request'}, status=400)

    client_id = params[TokenRequest.CLIENT_ID]
    client_secret = params[TokenRequest.CLIENT_SECRET]

    # Check if client is registered
    if not verify_client(client_id, client_secret):
        return web.json_response(data={'error': 'unauthorized_client'}, status=400)

    # Extract Clients Public key
    client_pk = jwk.JWK()
    client_pk.import_key(**params[TokenRequest.CNF]['jwk'])

    # Extract client claims scope and audience
    client_claims = {k: params[k] for k in (TokenRequest.SCOPE, TokenRequest.AUD)}

    # Issue Token
    tkn = Token.make_token(client_claims, client_pk, SIGNATURE_KEY, CRYPTO_KEY)

    return web.json_response(tkn)


def main():
    app = web.Application()

    app.router.add_get('/clients', clients)
    app.router.add_post('/token', token)

    web.run_app(app, port=8080)


if __name__ == "__main__":
    main()
