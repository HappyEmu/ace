from aiohttp import web


class HttpServer:

    def start(self, port: int):
        app = web.Application()
        self.on_start(app.router)

        web.run_app(app, port=port)

    def on_start(self, router):
        pass
