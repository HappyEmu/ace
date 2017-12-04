import jwt
from jwcrypto.common import json_decode


class Token(object):

    @staticmethod
    def make_token(session_key, signature_key, enc_key):
        # Bind session key to token
        payload = {
            'iss': 'test',
            'aud': 'tempSensor0',
            'cnf': {
                'jwk': json_decode(session_key.export())
            }
        }

        # Create signed JWT
        token = jwt.encode(payload, signature_key, algorithm='HS256')

        # PoP Token
        return {'access_token': token.decode('utf-8'),
                'token_type': 'pop',
                'csp': 'DTLS', }
