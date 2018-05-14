from inspect import currentframe, getframeinfo
import base64
import binascii

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login as authLogin, logout as authLogout
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse

from .models import apiCall, apiLogin, apiGetToken, apiLogout


def login(request):
    if request.session.get('token') is None:
        # There is no token in the session. Authenticate against IDP
        authorization_url = apiLogin(request, request.build_absolute_uri(reverse('authfib:callback')))
        if not authorization_url:
            messages.add_message(request, messages.ERROR,
                                 'IDP (%d) Unknown error' % (getframeinfo(currentframe()).lineno))
            return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)
        return HttpResponseRedirect(authorization_url)
    else:
        # Select user that corresponds to session token
        user = authenticate(request)
        if user is not None:
            authLogin(request, user)
        return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)


def logout(request):
    apiLogout(request)
    authLogout(request)
    return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)


def profile(request):
    if request.user.is_authenticated:
        result = apiCall(request, uri='jo/', accept_type='application/json')
        user = {
            'nom': result['nom'],
            'cognoms': result['cognoms'],
            'email': result['email'],
            'username': result['username'],
        }

        result_type, result_object = apiCall(request, uri='jo/foto.jpg')
        user['foto'] = 'data:%s;base64, %s' % (result_type, base64.b64encode(result_object).decode())

        result = apiCall(request, uri='jo/assignatures/', accept_type='application/json')
        user['subjects'] = []
        for subject in result['results']:
            user['subjects'].append({
                'id': subject['id'], 'nom': subject['nom'], 'grup': subject['grup']
            })

        result = apiCall(request, uri='jo/avisos/', accept_type='application/json')
        user['notices'] = []
        for notice in result['results']:
            user['notices'].append({
                'titol': notice['titol'], 'codi_assig': notice['codi_assig'], 'text': notice['text'], 'data_modificacio': notice['data_modificacio']
            })
        return render(request, 'profile.html', user)
    return render(request, 'profile.html')


def callback(request):
    params = request.GET.keys()
    if 'code' in params:
        if apiGetToken(request, request.build_absolute_uri(reverse('authfib:callback'))):
            user = authenticate(request)
            if user is not None:
                authLogin(request, user)
        return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)

    elif 'error' in params:
        messages.add_message(request, messages.ERROR,
                             'IDP (%d) %s' % (getframeinfo(currentframe()).lineno, request.GET['error']))

    else:
        messages.add_message(request, messages.ERROR,
                             'IDP (%d) Unknown error' % getframeinfo(currentframe()).lineno)
    return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)
