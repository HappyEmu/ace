class TokenCache(object):

    def __init__(self):
        self.tokens = {}

    def add_token(self, token, pop_key_id):
        self.tokens[pop_key_id] = token

    def get_token(self, pop_key_id):
        return self.tokens[pop_key_id]

