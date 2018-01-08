import binascii

import os


class TokenCache(object):

    def __init__(self):
        self.tokens = {}

    def add_token(self, token):
        cti = binascii.hexlify(os.urandom(16)).decode('utf-8')
        self.tokens[cti] = token

        return cti

    def get_token(self, cti):
        return self.tokens[cti]
