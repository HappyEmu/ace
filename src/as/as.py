from access_token import Token
from client_registry import ClientRegistry
from flask import Flask, jsonify, request
from jwcrypto import jwk

CRYPTO_KEY = '123456789'
SIGNATURE_KEY = '723984572'


# Verifies that
def verify_token_request():
    expected_keys = ['grant_type',
                     'client_id',
                     'client_secret',
                     'aud']

    if request.get_json() is None:
        return False

    return all(key in request.get_json() for key in expected_keys)


def verify_client(client_id, client_secret):
    return client_registry.check_secret(client_id, client_secret)


app = Flask(__name__)

client_registry = ClientRegistry()
client_registry.register_client(client_id="123456789", client_secret="verysecret")


# Clients endpoint
#
# Returns a list of all approved client IDs.
# ONLY FOR DEBUGGING PURPOSES
@app.route("/clients")
def clients():
    return jsonify({'approved_clients': [c.client_id for c in client_registry.registered_clients]})


# Token endpoint
#
# Validates the incoming requests and grants an access token if valid. Must be POST [ACE 5.6.1]
# Returns error codes as stated in [ACE 5.6.3]
@app.route("/token", methods=['POST'])
def token():
    # Verify basic request
    if not verify_token_request():
        return jsonify({'error': 'invalid_request'}), 400

    params = request.get_json()

    client_id = params['client_id']
    client_secret = params['client_secret']

    # Check if client is registered
    if not verify_client(client_id, client_secret):
        return jsonify({'error': 'unauthorized_client'}), 400

    # Extract Clients Public key
    client_pk = jwk.JWK()
    client_pk.import_key(**params['cnf']['jwk'])

    # Extract client claims scope and audience
    client_claims = {k: params[k] for k in ('scope', 'aud')}

    # Issue Token
    tkn = Token.make_token(client_claims, client_pk, SIGNATURE_KEY, CRYPTO_KEY)

    return jsonify(tkn)


def main():
    app.run(port=8080)


if __name__ == "__main__":
    main()
