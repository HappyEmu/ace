from . import TemperatureServer
from ecdsa import VerifyingKey, SigningKey

rs_identity = SigningKey.from_der(
    bytes.fromhex(
        "307702010104200ffc411715d3cc4917bd27ac4f310552b085b1ca0bb0a8"
        "bbb9d8931d651544c1a00a06082a8648ce3d030107a144034200046cc415"
        "12d92fb03cb3b35bed5b494643a8a8a55503e87a90282c78d6c58a7e3c88"
        "a21c0287e7e8d76b0052b1f1a2dcebfea57714c1210d42f17b335adcb76d"
        "7a"
    )
)

as_public_key = VerifyingKey.from_der(
    bytes.fromhex(
        "3059301306072a8648ce3d020106082a8648ce3d030107034200047069be"
        "d49cab8ffa5b1c820271aef0bc0c8f5cd149e05c5b9e37686da06d02bd5f"
        "7bc35ea8265be7c5e276ad7e7d0eb05e4a0551102a66bba88b02b5eb4c33"
        "55"
    )
)

server = TemperatureServer(
    audience="tempSensor0",
    identity=rs_identity,
    as_url='http://localhost:8080',
    as_public_key=as_public_key
)

server.start(port=8081)
