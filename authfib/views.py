from inspect import currentframe, getframeinfo

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
        return render(request, 'profile.html', result)
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
