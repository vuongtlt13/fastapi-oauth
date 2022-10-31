"""
    Implementation of Accessing Protected Resources per `Section 7`_.

    .. _`Section 7`: https://tools.ietf.org/html/rfc6749#section-7
"""
import asyncio
import functools
import logging
from contextlib import contextmanager
from typing import Dict, List, Optional, Tuple, Union

from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status
from starlette.requests import Request

from ..common.context import OAuthContext
from ..common.errors import OAuth2Error
from .errors import MissingAuthorizationError, UnsupportedTokenTypeError
from .mixins import TokenMixin, UserMixin
from .signals import token_authenticated
from .util import scope_to_list

_logger = logging.getLogger(__name__)


class TokenValidator(object):
    """Base token validator class. Subclass this validator to register
    into ResourceProtector instance.
    """
    TOKEN_TYPE = 'bearer'

    def __init__(self, realm=None, **extra_attributes):
        self.realm = realm
        self.extra_attributes = extra_attributes

    @staticmethod
    def scope_insufficient(token_scopes: str, required_scopes: List[str]) -> bool:
        """
            Check token scopes contain all require scopes.

            Return False if Token scopes contain all require scopes,
            it means token is valid and can continue the request.

            Otherwise return True, it means token invalid for require scopes.
            Must raise Error and block request!

        :param token_scopes:  Token scopes in current request
        :param required_scopes: Require scopes to continue request
        :return: Return bool
        """
        if not required_scopes:
            return False

        token_scopes_list = scope_to_list(token_scopes)
        if not token_scopes_list:
            return True

        token_scopes_set = set(token_scopes_list)
        return not token_scopes_set.issuperset(set(required_scopes))

    async def authenticate_token(self, token_string: str, session: AsyncSession) -> Optional[TokenMixin]:
        """A method to query token from database with the given token string.
        Developers MUST re-implement this method. For instance::

            def authenticate_token(self, token_string):
                return get_token_from_database(token_string)

        :param session: async SQLAlchemy session
        :param token_string: A string to represent the access_token.
        :return: token
        """
        raise NotImplementedError()

    async def query_user(self, token: TokenMixin, session: AsyncSession) -> Optional[UserMixin]:
        """A method to query token from database with the given token string.
        Developers MUST re-implement this method. For instance::

            def authenticate_token(self, token_string):
                return get_token_from_database(token_string)

        :param session: async SQLAlchemy session
        :param token: TokenMixin object.
        :return: user
        """
        raise NotImplementedError()

    def validate_request(self, request: Request):
        """A method to validate if the HTTP request is valid or not. Developers MUST
        re-implement this method.  For instance, your server requires an
        "X-Device-Version" in the header::

            def validate_request(self, request):
                if 'X-Device-Version' not in request.headers:
                    raise InvalidRequestError()

        Usually, you don't have to detect if the request is valid or not. If you have
        to, you MUST re-implement this method.

        :param request: instance of HttpRequest
        :raise: InvalidRequestError
        """
        raise NotImplementedError()

    def validate_token(self, token: Optional[TokenMixin], request: Request, scopes: List[str] = None):
        """A method to validate if the authorized token is valid, if it has the
        permission on the given scopes. Developers MUST re-implement this method.
        e.g, check if token is expired, revoked::

            def validate_token(self, token, scopes, request):
                if not token:
                    raise InvalidTokenError()
                if token.is_expired() or token.is_revoked():
                    raise InvalidTokenError()
                if not match_token_scopes(token, scopes):
                    raise InsufficientScopeError()
        """
        raise NotImplementedError()


class ResourceProtector(object):
    def __init__(self):
        self._token_validators: Dict[str, TokenValidator] = {}
        self._default_realm = None
        self._default_auth_type = None

    def register_token_validator(self, validator: TokenValidator):
        """Register a token validator for a given Authorization type.
        Authlib has a built-in BearerTokenValidator per rfc6750.
        """
        if not self._default_auth_type:
            self._default_realm = validator.realm
            self._default_auth_type = validator.TOKEN_TYPE

        if validator.TOKEN_TYPE not in self._token_validators:
            self._token_validators[validator.TOKEN_TYPE] = validator

    def get_token_validator(self, token_type):
        """Get token validator from registry for the given token type."""
        validator = self._token_validators.get(token_type.lower())
        if not validator:
            raise UnsupportedTokenTypeError(self._default_auth_type, self._default_realm)
        return validator

    def parse_request_authorization(self, request: Request) -> Tuple[TokenValidator, str]:
        """Parse the token and token validator from request Authorization header.
        Here is an example of Authorization header::

            Authorization: Bearer a-token-string

        This method will parse this header, if it can find the validator for
        ``Bearer``, it will return the validator and ``a-token-string``.

        :return: validator, token_string
        :raise: MissingAuthorizationError
        :raise: UnsupportedTokenTypeError
        """
        auth = request.headers.get('authorization')
        if not auth:
            raise MissingAuthorizationError(self._default_auth_type, self._default_realm)

        # https://tools.ietf.org/html/rfc6749#section-7.1
        token_parts = auth.split(None, 1)
        if len(token_parts) != 2:
            raise UnsupportedTokenTypeError(self._default_auth_type, self._default_realm)

        token_type, token_string = token_parts
        validator = self.get_token_validator(token_type)
        return validator, token_string

    async def validate_request(self, context: OAuthContext, scopes: List[str] = None) -> Optional[TokenMixin]:
        """Validate the request and return a token."""
        validator, token = await self.get_token_from_request(context)
        validator.validate_token(
            token=token,
            scopes=scopes,
            request=context.request.raw_request,
        )
        user = None
        if token and hasattr(validator, 'query_user') and context.session:
            user = await validator.query_user(token=token, session=context.session)

        context.token = token
        context.user_from_token = user
        return token

    async def acquire_token(self, context: OAuthContext, scopes: List[str] = None) -> Optional[TokenMixin]:
        """A method to acquire current valid token with the given scope.

        :param context: OAuthContext context
        :param scopes: a list of scope values
        :return: token object
        """
        token = await self.validate_request(context=context, scopes=scopes)
        token_authenticated.send(self, token=token)
        return token

    @contextmanager
    def acquire(self, context: OAuthContext, scopes: List[str] = None):
        """The with statement of ``require_oauth``. Instead of using a
        decorator, you can use a with statement instead::

            @app.route('/api/user')
            def user_api():
                with require_oauth.acquire('profile') as token:
                    user = User.query.get(token.user_id)
                    return jsonify(user.to_dict())
        """
        try:
            yield self.acquire_token(context=context, scopes=scopes)
        except OAuth2Error:
            raise

    def require_scope(self, scopes: Union[List[str], str] = None, optional=False):
        if isinstance(scopes, str):
            scopes = [scopes]

        def wrapper(f):
            @functools.wraps(f)
            async def decorated(*args, **kwargs):
                # find context object
                context: Optional[OAuthContext] = None
                for arg in args:
                    if isinstance(arg, OAuthContext):
                        context = arg

                for _, v in kwargs.items():
                    if isinstance(v, OAuthContext):
                        context = v

                if context is None:
                    _logger.error(
                        'You must add `OAuthContext` argument in your function! '
                        'Just use dependency `AuthorizationServer.get_oauth_context`',
                    )
                    raise OAuth2Error(
                        description='You must add `OAuthContext` argument in your function! '
                                    'Just use dependency `AuthorizationServer.get_oauth_context`',
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    )

                try:
                    await self.acquire_token(context=context, scopes=scopes)
                except MissingAuthorizationError:
                    if optional:
                        if asyncio.iscoroutinefunction(f):
                            return await f(*args, **kwargs)

                        return f(*args, **kwargs)
                    raise
                except OAuth2Error:
                    raise

                if asyncio.iscoroutinefunction(f):
                    return await f(*args, **kwargs)

                return f(*args, **kwargs)

            return decorated

        return wrapper

    async def get_token_from_request(self, context: OAuthContext) -> Tuple[TokenValidator, Optional[TokenMixin]]:
        validator, token_string = self.parse_request_authorization(context.request.raw_request)
        validator.validate_request(context.request.raw_request)
        if context.session:
            token = await validator.authenticate_token(token_string, context.session)
        else:
            token = None

        return validator, token
