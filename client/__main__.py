from cbor2 import dumps
from . import Client

AS_URL = 'http://localhost:8080'
RS_URL = 'http://localhost:8081'


client = Client(client_id='ace_client_1',
                client_secret=b'ace_client_1_secret_123456')

client2 = Client(client_id='ace_client_2',
                 client_secret=b'ace_client_2_secret_456789')

# Request access token
session = client.request_access_token(
    as_url=AS_URL,
    audience="tempSensor0",
    scopes=["read_temperature", "post_led"]
)

# Request access token
session2 = client2.request_access_token(
    as_url=AS_URL,
    audience="tempSensor0",
    scopes=["read_temperature", "post_led"]
)

# Upload token to RS
client.upload_access_token(session, RS_URL, '/authz-info')
client2.upload_access_token(session2, RS_URL, '/authz-info')

# Access temperature resource
response = client.access_resource(session, RS_URL + '/temperature')
print(f"Response: {response}")

# Update resource on RS
data = { b'led_value': 1 }
response = client.post_resource(session, RS_URL + '/led', dumps(data))
print(f"Response: {response}")

# Access temperature resource
response = client2.access_resource(session2, RS_URL + '/temperature')
print(f"Response: {response}")

# Update resource on RS
data = { b'led_value': 1 }
response = client2.post_resource(session2, RS_URL + '/led', dumps(data))
print(f"Response: {response}")
