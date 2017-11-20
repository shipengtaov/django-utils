# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.contrib.auth import get_user_model

from front.models import UserProfile, ChefProfile
from .utils import get_login_code


UserModel = get_user_model()


class PhoneCodeBackend(object):
    """通过手机号，验证码认证."""

    def authenticate(self, request=None, **credentials):
        if request is not None:
            phone_number = request.POST.get('phone_number')
            phone_code = request.POST.get('phone_code')
            login_type = request.POST.get('login_type', 'user')
            if not phone_number or not phone_code:
                return None
            if login_type not in ('user', 'chef'):
                return None
            # if get_login_code(phone_number) != phone_code:
            #     return None
            try:
                if login_type == 'user':
                    profile = UserProfile.objects.get(phone_number=phone_number)
                elif login_type == 'chef':
                    profile = ChefProfile.objects.get(phone_number=phone_number)
            except (UserProfile.DoesNotExist, ChefProfile.DoesNotExist):
                return None
            return profile.user

        return None

    def get_user(self, user_id):
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
