from cbor2 import dumps, loads
from . import Client, AS_URL, RS_URL


client = Client(client_id='ace_client_1',
                client_secret=b'ace_client_1_secret_123456')

client.start_new_session()

client.request_access_token(AS_URL)
client.upload_access_token(RS_URL)
edhoc_session = client.establish_secure_context()

response = client.access_resource(edhoc_session, RS_URL + '/temperature')
print(f"Response: {response}")

data = { b'led_value': 1 }
response = client.post_resource(edhoc_session, RS_URL + '/led', dumps(data))
print(f"Response: {response}")
