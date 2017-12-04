import requests

CLIENT_ID = '123456789'
CLIENT_SECRET = 'verysecret'

AS_URL = 'http://localhost:8080'
RS_URL = 'http://localhost:8081'


def main():
    token_request = {'grant_type': 'client_credentials',
                     'client_id': CLIENT_ID,
                     'client_secret': CLIENT_SECRET,
                     'aud': 'tempSens1'}

    response = requests.post(AS_URL + '/token', json=token_request)

    if response.status_code == 200:
        token = response.json()
    else:
        token = None

    if token:
        print(f"Got token: {token}")
    else:
        print("Did not get token :(")


if __name__ == '__main__':
    main()
