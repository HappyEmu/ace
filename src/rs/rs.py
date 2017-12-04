from flask import Flask, jsonify

AS_CRYPTO_KEY = '123456789'
AS_SIGNATURE_KEY = '723984572'

AUDIENCE = 'tempSens1'

app = Flask(__name__)


@app.route("/temperature")
def temperature():
    request.get_json()
    return jsonify({'temperature': '32C'})


def main():
    app.run(port=8081)


if __name__ == "__main__":
    main()
