from django.contrib.auth import get_user_model
from django.conf import settings
import requests
import json
from .models import apiCall

UserModel = get_user_model()


class Oauth2Backend:
    def authenticate(self, request, **kwargs):
        result = apiCall(request, uri='jo/', accept_type='application/json')
        if result is None:
            return None
        username = kwargs.get(UserModel.USERNAME_FIELD)
        if username is not None and result['username'] != username:
            # if trying to authenticate a different user with username and password fail
            return None
        try:
            user = UserModel._default_manager.get_by_natural_key(result['username'])
        except UserModel.DoesNotExist:
            # Oauth2 authenticated user does not exist locally, create it!
            user = UserModel.objects.create_user(username=result['username'], first_name=result['nom'],
                                            last_name=result['cognoms'], email=result['email'])
        # User existed or has been created. Now check if it is active
        return user if self.user_can_authenticate(user) else None

    def get_user(self, user_id):
        try:
            user = UserModel._default_manager.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
        return user if self.user_can_authenticate(user) else None

    def user_can_authenticate(self, user):
        """
        Reject users with is_active=False. Custom user models that don't have
        that attribute are allowed.
        """
        is_active = getattr(user, 'is_active', None)
        return is_active or is_active is None
