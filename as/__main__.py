from . import SigningKey, AuthorizationServer


sk = SigningKey.from_der(bytes.fromhex("30770201010420fb37dbd38e48cfc41475e50dd52d7328102bd31cf881e4"
                                       "e163c58e5f150aa1f2a00a06082a8648ce3d030107a144034200047069be"
                                       "d49cab8ffa5b1c820271aef0bc0c8f5cd149e05c5b9e37686da06d02bd5f"
                                       "7bc35ea8265be7c5e276ad7e7d0eb05e4a0551102a66bba88b02b5eb4c33"
                                       "55"))

server = AuthorizationServer(signature_key=sk)
server.start(port=8080)
