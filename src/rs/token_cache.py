import binascii

import os


class TokenCache(object):

    def __init__(self):
        self.tokens = {}
        self.pop_keys = {}

    def add_token(self, token, pop_key):
        cti = binascii.hexlify(os.urandom(16)).decode('ascii')
        self.tokens[cti] = token
        self.pop_keys[cti] = pop_key

        return cti

    def get_token(self, cti):
        return self.tokens[cti]

    def get_pop_key(self, cti):
        return self.pop_keys[cti]
