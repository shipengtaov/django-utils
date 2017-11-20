# -*- coding: utf-8 -*-

"""从 django-oauth-toolkit 抽离出生成 token 的函数.

curl -X POST -d "grant_type=password&username=<user_name>&password=<password>" -u"<client_id>:<client_secret>" http://localhost:8000/o/token/  # noqa
"""

from __future__ import unicode_literals

import json

from django.contrib.auth import get_user_model
from django.http import HttpResponse

from rest_framework.response import Response

from oauth2_provider.models import get_access_token_model
from oauthlib.common import quote, urlencode, urlencoded
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.oauth2_validators import OAuth2Validator

from common.compat import urlparse, urlunparse


class Validator(OAuth2Validator):
    """自定义validator，直接返回指定用户."""
    def validate_user(self, username, password, client, request, *args, **kwargs):
        """
        Check username and password correspond to a valid and active User
        """
        u = get_user_model().objects.get(username=username)
        if u is not None and u.is_active:
            request.user = u
            return True
        return False
        # u = authenticate(username=username, password=password)
        # if u is not None and u.is_active:
        #     request.user = u
        #     return True
        # return False


class CreateTokenMixin(object):
    """代码修改自django-oauth-toolkit."""

    server = oauth2_settings.OAUTH2_SERVER_CLASS(Validator())

    def create_token_for_user(self, request, username,
                              response_type='rest_framework'):
        """只有此方法供外部调用.

        Args:
            - username: 需要为哪个用户生成token；auth_user 表中的 username
            - response_type: response 返回类型；django, rest_framework 二选一
        """
        # url, headers, body, status = self.create_token_response(request)
        server = self.server
        uri = self._get_escaped_full_path(request)
        http_method = request.method
        headers = self.extract_headers(request)
        body = urlencode(self.extract_body(request, username=username))

        headers, body, status = server.create_token_response(
            uri, http_method, body, headers, dict())
        uri = headers.get("Location", None)

        access_token = None
        if status == 200:
            access_token = json.loads(body).get("access_token")
            if access_token is not None:
                token = get_access_token_model().objects.get(token=access_token)

        if response_type == 'rest_framework':
            response = Response(data=body, status=status, headers=headers)
        elif response_type == 'django':
            response = HttpResponse(content=body, status=status)
            for k, v in headers.items():
                response[k] = v
        else:
            raise Exception('response_type error: {}'.format(response_type))

        return dict(
            access_token=access_token,
            headers=headers,
            body=body,
            body_dict=json.loads(body),
            status=status,
            response=response,
        )

    def _get_escaped_full_path(self, request):
        """
        Django considers "safe" some characters that aren't so for oauthlib.
        We have to search for them and properly escape.
        """
        parsed = list(urlparse(request.get_full_path()))
        unsafe = set(c for c in parsed[4]).difference(urlencoded)
        for c in unsafe:
            parsed[4] = parsed[4].replace(c, quote(c, safe=b""))

        return urlunparse(parsed)

    def extract_headers(self, request):
        """
        Extracts headers from the Django request object
        :param request: The current django.http.HttpRequest object
        :return: a dictionary with OAuthLib needed headers
        """
        headers = request.META.copy()
        if "wsgi.input" in headers:
            del headers["wsgi.input"]
        if "wsgi.errors" in headers:
            del headers["wsgi.errors"]
        if "HTTP_AUTHORIZATION" in headers:
            headers["Authorization"] = headers["HTTP_AUTHORIZATION"]

        return headers

    def extract_body(self, request, username):
        """
        Extracts the POST body from the Django request object
        :param request: The current django.http.HttpRequest object
        :return: provided POST parameters
        """
        post = request.POST.copy()
        post['username'] = username
        post['password'] = 'test'
        return post.items()
