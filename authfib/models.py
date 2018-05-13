import json
from inspect import currentframe, getframeinfo
from werkzeug import security

import requests
from django.conf import settings
from django.contrib import messages
from requests_oauthlib import OAuth2Session


# Get URL to redirect to IDP to ask end user for credentials
def apiLogin(request, redirect_uri):
    oauth = OAuth2Session(client_id=settings.AUTH_CLIENT_ID, redirect_uri=redirect_uri, scope=settings.AUTH_SCOPE)
    random_state = security.gen_salt(16)
    authorization_url, state = oauth.authorization_url(settings.AUTH_URL + 'o/authorize/', state=random_state)
    return authorization_url if state == random_state else False


# Get session token to authorize API calls
def apiGetToken(request, redirect_uri):
    oauth = OAuth2Session(client_id=settings.AUTH_CLIENT_ID, redirect_uri=redirect_uri, scope=settings.AUTH_SCOPE)
    try:
        token = oauth.fetch_token(settings.AUTH_URL + 'o/token/', code=request.GET['code'],
                                  client_secret=settings.AUTH_CLIENT_SECRECT)
    except Exception as e:
        messages.add_message(request, messages.ERROR,
                             'IDP (%d) [%s]' % (getframeinfo(currentframe()).lineno, e.error))
        return False

    request.session['token'] = '%s %s' % (token['token_type'], token['access_token'])
    request.session['refresh_token'] = token['refresh_token']
    request.session.set_expiry(token['expires_in'])
    return True

def apiLogout(request):
    headers = {'Cache-Control': 'no-cache',
               'Accept': 'application/json',
               'Content-Type': 'application/x-www-form-urlencoded',
               }
    data = {
        'client_id': settings.AUTH_CLIENT_ID,
        'token': request.session.get('token'),
    }
    response = requests.post(url=settings.AUTH_URL + 'o/revoke_token/', data=data, headers=headers)
    if response.status_code != 200:
        messages.add_message(request, messages.ERROR,
                             'IDP (%d) [%s]' % (getframeinfo(currentframe()).lineno, response.reason))
        return
    return


def apiCall(request, uri, accept='application/json'):
    headers = {'Cache-Control': 'no-cache',
               'Accept': accept,
               'Authorization': request.session.get('token'),
               }
    response = requests.get(url=settings.AUTH_URL + uri, headers=headers)
    if response.status_code != 200:
        messages.add_message(request, messages.ERROR,
                             'IDP (%d) [%s]' % (getframeinfo(currentframe()).lineno, response.reason))
        return None
    if accept == 'application/json':
        return json.loads(response.text)
    else:
        return None
