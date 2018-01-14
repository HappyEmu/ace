import logging

import asyncio

import aiocoap.resource as resource
import aiocoap


class CoapServer:

    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        logging.getLogger(self.server_name).setLevel(logging.DEBUG)

    def start(self):
        # Resource tree creation
        root = resource.Site()
        self.on_start(root)
        self.after_start()

        asyncio.Task(aiocoap.Context.create_server_context(root))
        asyncio.get_event_loop().run_forever()

    def on_start(self, site):
        """Delegate to implementation"""
        pass

    def after_start(self):
        logging.info("Started COAP Server at:")
