from flask import Flask, jsonify, request


class Client:
    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret


# Verifies that
def verify_token_request():
    expected_keys = ['grant_type',
                     'client_id',
                     'client_secret',
                     'aud']

    if request.get_json() is None:
        return False

    return all(key in expected_keys for key in request.get_json())


def verify_client(client_id, client_secret):
    is_registered = client_id in [c.client_id for c in approved_clients]

    if is_registered:
        registered_secret = [c.client_secret for c in approved_clients if c.client_id == client_id][0]

        if registered_secret == client_secret:
            return True

    return False


app = Flask(__name__)
approved_clients = [Client("123456789", "verysecret")]


# Clients endpoint
#
# Returns a list of all approved client IDs.
# ONLY FOR DEBUGGING PURPOSES
@app.route("/clients")
def clients():
    return jsonify({'approved_clients': [c.client_id for c in approved_clients]})


# Token endpoint
#
# Validates the incoming requests and grants an access token if valid. Must be POST [ACE 5.6.1]
# Returns error codes as stated in [ACE 5.6.3]
@app.route("/token", methods=['POST'])
def token():
    # Verify basic request
    if not verify_token_request():
        return jsonify({'error': 'invalid_request'}), 400

    client_id = request.get_json()['client_id']
    client_secret = request.get_json()['client_secret']

    # Check if client is registered
    if not verify_client(client_id, client_secret):
        return jsonify({'error': 'unauthorized_client'}), 400

    # Issue Token
    tkn = {'token': 'token'}

    return jsonify(tkn)


def main():
    app.run(port=8080)


if __name__ == "__main__":
    main()
