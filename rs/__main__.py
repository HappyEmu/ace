from . import ResourceServer


server = ResourceServer(audience="tempSensor0")
server.start(port=8081)
