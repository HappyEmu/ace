from lib.cose import CoseKey


class KeyRegistry:
    def __init__(self):
        self.registry = {}

    def add_key(self, client_id, key: CoseKey):
        self.registry[(client_id, key.key_id)] = key

    def find_key(self, client_id, key_id):
        return self.registry[(client_id, key_id)]

    def _has_key(self, client_id, key_id):
        return (client_id, key_id) in self.registry
