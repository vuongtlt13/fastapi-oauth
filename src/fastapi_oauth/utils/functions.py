import time
from typing import Any, Callable, Dict, Optional, Type, Union

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from werkzeug.utils import import_string

from ..common.context import OAuthContext
from ..common.errors import OAuth2Error
from ..common.security import generate_token
from ..common.types import ExpireTokenGenerator, QueryClientFn, QueryTokenFn, SaveTokenFn, SingleTokenGenerator
from ..rfc6749.mixins import ClientMixin, TokenMixin, UserMixin
from ..rfc6749.wrappers import OAuth2Request
from ..rfc6750.token import BearerTokenGenerator


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

    from ..rfc7009.revocation import RevocationEndpoint

    class _RevocationEndpoint(RevocationEndpoint):
        async def query_token(self, token: str, token_type_hint: str, session: AsyncSession):
            return await query_token(token=token, token_type_hint=token_type_hint, session=session)

        async def revoke_token(self, context: OAuthContext, token: TokenMixin):
            now = int(time.time())
            hint = context.request.token_type_hint
            token.access_token_revoked_at = now
            if hint != 'access_token':
                token.refresh_token_revoked_at = now

            if context.session:
                context.session.add(token)
                await context.session.commit()

    return _RevocationEndpoint


def create_bearer_token_validator(token_model: Type[TokenMixin], user_model: Type[UserMixin]):
    """Create a bearer token validator class with SQLAlchemy session
    and token model.

    :param user_model: User model class
    :param token_model: Token model class
    """
    from ..rfc6750.validator import BearerTokenValidator

    class _BearerTokenValidator(BearerTokenValidator):
        async def query_user(self, token: TokenMixin, session: AsyncSession) -> Optional[UserMixin]:
            q = select(user_model)
            return (await session.scalars(q.filter_by(id=token.user_id))).first()

        async def authenticate_token(self, token_string, session: AsyncSession) -> Optional[TokenMixin]:
            q = select(token_model)
            return (await session.scalars(q.filter_by(access_token=token_string))).first()

    return _BearerTokenValidator


async def create_oauth_request(request: Request, request_cls: Type[OAuth2Request], allow_insecure_transport=False):
    if isinstance(request, request_cls):
        return request

    oauth_request = request_cls(
        request=request,
        allow_insecure_transport=allow_insecure_transport,
    )
    await oauth_request.prepare_data()
    return oauth_request


def create_token_expires_in_generator(expires_in_conf: Union[Dict, str] = None) -> ExpireTokenGenerator:
    if isinstance(expires_in_conf, str):
        return import_string(expires_in_conf)

    data: Dict[str, int] = {}
    data.update(BearerTokenGenerator.GRANT_TYPES_EXPIRES_IN)
    if isinstance(expires_in_conf, dict):
        data.update(expires_in_conf)

    def expires_in(client: Any, grant_type: str):
        return data.get(grant_type, BearerTokenGenerator.DEFAULT_EXPIRES_IN)

    return expires_in


def create_token_generator(
    token_generator_conf: Union[Callable, bool, str],
    length: int,
    allow_none=False,
) -> Optional[SingleTokenGenerator]:
    if callable(token_generator_conf):
        return token_generator_conf

    if isinstance(token_generator_conf, str):
        return import_string(token_generator_conf)
    elif token_generator_conf is True:
        def token_generator(
            grant_type: str,
            client: ClientMixin,
            user=None,
            scope=None,
            expires_in: int = None,
            include_refresh_token: bool = True,
        ) -> str:
            return generate_token(length=length)

        return token_generator

    if allow_none:
        return None

    raise OAuth2Error("Can't create token generator!")
