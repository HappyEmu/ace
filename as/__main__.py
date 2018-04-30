from . import SigningKey, AuthorizationServer


sk = SigningKey.from_der(bytes.fromhex("307702010104203908b414f1a1f589e8de11a60cfc22fdff0182f093bf8cc40554087d"
                                       "7557cc43a00a06082a8648ce3d030107a144034200045aeec31f9e64aad45aba2d365e"
                                       "71e84dee0da331badab9118a2531501fd9861d027c9977ca32d544e6342676ef00fa43"
                                       "4b3aaed99f4823750517ca3390374753"))

server = AuthorizationServer(signature_key=sk)
server.start(port=8080)
