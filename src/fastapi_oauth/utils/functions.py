import time
from typing import Any, Dict, Type

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from werkzeug.utils import import_string

from ..common.security import generate_token
from ..common.types import QueryClientFn, QueryTokenFn, SaveTokenFn
from ..rfc6749.mixins import ClientMixin, TokenMixin
from ..rfc6749.models import OAuth2TokenBase
from ..rfc6749.wrappers import OAuth2Request
from ..rfc6750 import BearerTokenGenerator


def create_query_client_func(client_model: Type[ClientMixin]) -> QueryClientFn:
    """Create an ``query_client`` function that can be used in authorization
    server.

    :param client_model: Client model class
    """

    async def query_client(client_id: str, session: AsyncSession):
        q = select(client_model).filter_by(client_id=client_id)  # type: ignore
        return (await session.scalars(q)).first()

    return query_client


def create_save_token_func(token_model: Type[TokenMixin]) -> SaveTokenFn:
    """Create an ``save_token`` function that can be used in authorization
    server.

    :param token_model: Token model class
    """

    async def save_token(token: Dict, request: OAuth2Request, session: AsyncSession):
        if request.user:
            user_id = request.user.get_user_id()
        else:
            user_id = None
        client = request.client
        if client:
            item = token_model(
                client_id=client.client_id,
                user_id=user_id,
                **token
            )
            session.add(item)
            await session.commit()

    return save_token


def create_query_token_func(token_model: Type[TokenMixin]) -> QueryTokenFn:
    """Create an ``query_token`` function for revocation, introspection
    token endpoints.

    :param token_model: Token model class
    """

    async def query_token(token: str, token_type_hint: str, session: AsyncSession):
        q = select(token_model)
        if token_type_hint == 'access_token':
            return (await session.scalars(q.filter_by(access_token=token))).first()
        elif token_type_hint == 'refresh_token':
            return (await session.scalars(q.filter_by(refresh_token=token))).first()
        # without token_type_hint
        item = (await session.scalars(q.filter_by(access_token=token))).first()
        if item:
            return item
        return (await session.scalars(q.filter_by(refresh_token=token))).first()

    return query_token


def create_revocation_endpoint(token_model: Type[TokenMixin]):
    """Create a revocation endpoint class with SQLAlchemy session
    and token model.

    :param token_model: Token model class
    """
    query_token = create_query_token_func(token_model)

    from ..rfc7009 import RevocationEndpoint

    class _RevocationEndpoint(RevocationEndpoint):
        async def query_token(self, token: str, token_type_hint: str, session: AsyncSession):
            return await query_token(token, token_type_hint, session)

        async def revoke_token(self, token: TokenMixin, request: OAuth2Request, session: AsyncSession):
            now = int(time.time())
            hint = request.token_type_hint
            token.access_token_revoked_at = now
            if hint != 'access_token':
                token.refresh_token_revoked_at = now
            session.add(token)
            await session.commit()

    return _RevocationEndpoint


def create_bearer_token_validator(token_model: Type[TokenMixin]):
    """Create a bearer token validator class with SQLAlchemy session
    and token model.

    :param token_model: Token model class
    """
    from ..rfc6750 import BearerTokenValidator

    class _BearerTokenValidator(BearerTokenValidator):
        async def authenticate_token(self, token_string, session: AsyncSession):
            q = select(token_model)
            return (await session.scalars(q.filter_by(access_token=token_string))).first()

    return _BearerTokenValidator


async def create_oauth_request(request: Request, request_cls: Type[OAuth2Request]):
    if isinstance(request, request_cls):
        return request

    oauth_request = request_cls(request)
    await oauth_request.prepare_data()
    return oauth_request


def create_token_expires_in_generator(expires_in_conf=None):
    if isinstance(expires_in_conf, str):
        return import_string(expires_in_conf)

    data = {}
    data.update(BearerTokenGenerator.GRANT_TYPES_EXPIRES_IN)
    if isinstance(expires_in_conf, dict):
        data.update(expires_in_conf)

    def expires_in(client: Any, grant_type: str):
        return data.get(grant_type, BearerTokenGenerator.DEFAULT_EXPIRES_IN)

    return expires_in


def create_token_generator(token_generator_conf, length: int):
    if callable(token_generator_conf):
        return token_generator_conf

    if isinstance(token_generator_conf, str):
        return import_string(token_generator_conf)
    elif token_generator_conf is True:
        def token_generator(*args, **kwargs):
            return generate_token(length, *args, **kwargs)

        return token_generator
