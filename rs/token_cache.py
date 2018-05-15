class TokenCache(object):

    def __init__(self):
        self.token = None
        self.pop_key = None

    def add_token(self, token, pop_key):
        self.token = token
        self.pop_key = pop_key

    def get_token(self):
        return self.token

    def get_pop_key(self,):
        return self.pop_key
