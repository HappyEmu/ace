from flask import Flask, jsonify, request

AUDIENCE = 'tempSens1'

app = Flask(__name__)


@app.route("/temperature")
def temperature():
    return jsonify({'temperature': '32C'})


def main():
    app.run(port=8081)


if __name__ == "__main__":
    main()
