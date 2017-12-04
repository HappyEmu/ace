import jwt


class Token(object):

    @staticmethod
    def make_token(signature_key, enc_key):
        payload = {'test': 'hello'}
        token = jwt.encode(payload, signature_key, algorithm='HS256')

        return {'access_token': token.decode('utf-8'),
                'token_type': 'pop',
                'csp': 'DTLS',}
