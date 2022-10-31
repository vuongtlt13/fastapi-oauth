import functools
import json
from contextlib import contextmanager

from werkzeug.local import LocalProxy

from ..base import OAuth2Error
from ..rfc6749 import HttpRequest, MissingAuthorizationError
from ..rfc6749 import ResourceProtector as _ResourceProtector
from .errors import raise_http_exception
from .signals import token_authenticated


class ResourceProtector(_ResourceProtector):
    """
    TODO: update example for fastapi
    A protecting method for resource servers. Creating a ``require_oauth``
    decorator easily with ResourceProtector::

        from fastapi_oauth.provider import ResourceProtector

        require_oauth = ResourceProtector()

        # add bearer token validator
        from fastapi_oauth.rfc6750 import BearerTokenValidator
        from project.models import Token

        class MyBearerTokenValidator(BearerTokenValidator):
            def authenticate_token(self, token_string):
                return Token.query.filter_by(access_token=token_string).first()

            def request_invalid(self, request):
                return False

            def token_revoked(self, token):
                return False

        require_oauth.register_token_validator(MyBearerTokenValidator())

        # protect resource with require_oauth

        @app.route('/user')
        @require_oauth(['profile'])
        def user_profile():
            user = User.query.get(current_token.user_id)
            return jsonify(user.to_dict())

    """
    def raise_error_response(self, error):
        """Raise HTTPException for OAuth2Error. Developers can re-implement
        this method to customize the error response.

        :param error: OAuth2Error
        :raise: HTTPException
        """
        status = error.status_code
        body = json.dumps(dict(error.get_body()))
        headers = error.get_headers()
        raise_http_exception(status, body, headers)

    def acquire_token(self, scopes=None):
        """A method to acquire current valid token with the given scope.

        :param scopes: a list of scope values
        :return: token object
        """
        request = HttpRequest(
            _req.method,
            _req.full_path,
            _req.data,
            _req.headers,
        )
        request.req = _req
        # backward compatible
        if isinstance(scopes, str):
            scopes = [scopes]
        token = self.validate_request(scopes, request)
        token_authenticated.send(self, token=token)
        ctx = _app_ctx_stack.top
        ctx.authlib_server_oauth2_token = token
        return token

    @contextmanager
    def acquire(self, scopes=None):
        """The with statement of ``require_oauth``. Instead of using a
        decorator, you can use a with statement instead::

            @app.route('/api/user')
            def user_api():
                with require_oauth.acquire('profile') as token:
                    user = User.query.get(token.user_id)
                    return jsonify(user.to_dict())
        """
        try:
            yield self.acquire_token(scopes)
        except OAuth2Error as error:
            self.raise_error_response(error)

    def __call__(self, scopes=None, optional=False):
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                try:
                    self.acquire_token(scopes)
                except MissingAuthorizationError as error:
                    if optional:
                        return f(*args, **kwargs)
                    self.raise_error_response(error)
                except OAuth2Error as error:
                    self.raise_error_response(error)
                return f(*args, **kwargs)
            return decorated
        return wrapper


def _get_current_token():
    ctx = _app_ctx_stack.top
    return getattr(ctx, 'authlib_server_oauth2_token', None)


current_token = LocalProxy(_get_current_token)
