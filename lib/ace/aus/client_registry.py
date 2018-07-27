from typing import List


class Client(object):
    def __init__(self, client_id, client_secret, grants):
        self.client_id = client_id
        self.client_secret = client_secret
        self.grants = grants


class ClientRegistry(object):
    def __init__(self):
        self._registered_clients = []

    @property
    def registered_clients(self) -> List[Client]:
        """
        :return: A list of all registered clients
        """
        return self._registered_clients

    def register_client(self, client: Client):
        """
        Register a client
        :param client: Pre-made Client object
        """
        self._registered_clients.append(client)

    def client_exists(self, client_id: str):
        """
        :param client_id: The client's ID
        :return: True if client_id is a registered client
        """
        return client_id in [c.client_id for c in self.registered_clients]

    def check_secret(self, client_id: str, client_secret: bytes):
        """
        :param client_id: The client's ID
        :param client_secret: The clients's secret to be tested
        :return: True if the client_secret passed to this function belongs to the registered client
        """
        if not self.client_exists(client_id):
            return False

        registered_secret = [c.client_secret for c in self.registered_clients if c.client_id == client_id][0]

        return registered_secret == client_secret
