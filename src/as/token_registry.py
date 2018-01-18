from lib.access_token import AccessToken


class TokenRegistry:

    def __init__(self):
        self.tokens_by_cti = {}
        self.tokens_by_ref = {}

    def add_token(self, token: AccessToken, self_contained=True):
        if self_contained:
            self.tokens_by_cti[token.cti] = token
        else:
            self.tokens_by_ref[token.reference] = token

    def get_token(self, reference=None, cti=None) -> AccessToken:
        if cti is not None:
            return self.tokens_by_cti[cti]

        return self.tokens_by_ref[reference]
