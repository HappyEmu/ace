from . import AuthorizationServer, Grant
from ecdsa import VerifyingKey, SigningKey

# Provision private key of authorization server
as_identity = SigningKey.from_der(bytes.fromhex("30770201010420fb37dbd38e48cfc41475e50dd52d7328102bd31cf881e4"
                                                "e163c58e5f150aa1f2a00a06082a8648ce3d030107a144034200047069be"
                                                "d49cab8ffa5b1c820271aef0bc0c8f5cd149e05c5b9e37686da06d02bd5f"
                                                "7bc35ea8265be7c5e276ad7e7d0eb05e4a0551102a66bba88b02b5eb4c33"
                                                "55"))

server = AuthorizationServer(identity=as_identity)

# Pre-register clients
server.register_client(
    client_id="ace_client_1",
    client_secret=b"ace_client_1_secret_123456",
    grants=[
        Grant(audience="tempSensor0", scopes=["read_temperature", "post_led"])
    ]
)

server.register_client(
    client_id="ace_client_2",
    client_secret=b"ace_client_2_secret_456789",
    grants=[
        Grant(audience="tempSensor0", scopes=["read_temperature"])
    ]
)

# Pre-register resource server
server.register_resource_server(
    audience="tempSensor0",
    scopes=['read_temperature', 'post_led'],
    public_key=VerifyingKey.from_der(
        bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200046cc415"
                      "12d92fb03cb3b35bed5b494643a8a8a55503e87a90282c78d6c58a7e3c88"
                      "a21c0287e7e8d76b0052b1f1a2dcebfea57714c1210d42f17b335adcb76d"
                      "7a")
    )
)

server.start(port=8080)
