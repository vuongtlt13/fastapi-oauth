"""
    Validate Bearer Token for in request, scope and token.
"""
from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from ..rfc6749.mixins import TokenMixin, UserMixin
from ..rfc6749.resource_protector import TokenValidator
from .errors import InsufficientScopeError, InvalidTokenError


class BearerTokenValidator(TokenValidator):
    def validate_request(self, request: Request):
        return True

    TOKEN_TYPE = 'bearer'

    async def authenticate_token(self, token_string, session: AsyncSession) -> Optional[TokenMixin]:
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

    def validate_token(self, token: Optional[TokenMixin], request, scopes: List[str] = None):
        """Check if token is active and matches the requested scopes.
        :param token: Token instance
        :param request: Request instance
        :param scopes: require scopes for the request
        """
        if not token:
            raise InvalidTokenError(realm=self.realm, extra_attributes=self.extra_attributes)
        if token.is_expired():
            raise InvalidTokenError(realm=self.realm, extra_attributes=self.extra_attributes)
        if token.is_revoked():
            raise InvalidTokenError(realm=self.realm, extra_attributes=self.extra_attributes)
        if self.scope_insufficient(token.get_scope(), scopes):
            raise InsufficientScopeError()
