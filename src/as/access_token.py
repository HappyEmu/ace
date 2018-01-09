import jwt
from jwcrypto.common import json_decode

from lib.cbor.constants import Keys as CborKeys


class Token(object):

    @staticmethod
    def make_token(client_claims, session_key, signature_key, enc_key):

        # Bind session key to token
        claims = { CborKeys.ISS: 'test',
                   CborKeys.CNF: { 'jwk': json_decode(session_key.export()) } }

        # Add client claims (aud and scope)
        claims.update(client_claims)

        # Create signed JWT
        token = jwt.encode(claims, signature_key, algorithm='HS256')

        # PoP Token
        return {'access_token': token.decode('utf-8'),
                'token_type': 'pop',
                'csp': 'coap_dtls', }

        # TODO: return Public Key of RS in 'rs_cnf'

        # Note: no 'cnf' param for asymmetric PoP keys
