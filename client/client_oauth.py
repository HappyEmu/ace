from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session

client_id = '123456789'
client_secret = 'verysecret'

client = BackendApplicationClient(client_id=client_id)
oauth = OAuth2Session(client=client)

token = oauth.fetch_token(token_url='https://provider.com/oauth2/token',
                          client_id=client_id,
                          client_secret=client_secret)
