import time

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


def create_query_client_func(client_model):
    """Create an ``query_client`` function that can be used in authorization
    server.

    :param client_model: Client model class
    """

    async def query_client(client_id, session: AsyncSession):
        q = select(client_model).filter_by(client_id=client_id)
        return (await session.scalars(q)).first()

    return query_client


def create_save_token_func(token_model):
    """Create an ``save_token`` function that can be used in authorization
    server.

    :param token_model: Token model class
    """

    async def save_token(token, request, session: AsyncSession):
        if request.user:
            user_id = request.user.get_user_id()
        else:
            user_id = None
        client = request.client
        item = token_model(
            client_id=client.client_id,
            user_id=user_id,
            **token
        )
        session.add(item)
        await session.commit()

    return save_token


def create_query_token_func(token_model):
    """Create an ``query_token`` function for revocation, introspection
    token endpoints.

    :param token_model: Token model class
    """

    async def query_token(token, token_type_hint, session: AsyncSession):
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


def create_revocation_endpoint(token_model):
    """Create a revocation endpoint class with SQLAlchemy session
    and token model.

    :param token_model: Token model class
    """
    query_token = create_query_token_func(token_model)

    from ..rfc7009 import RevocationEndpoint

    class _RevocationEndpoint(RevocationEndpoint):
        async def query_token(self, token, token_type_hint, session: AsyncSession):
            return await query_token(token, token_type_hint, session)

        async def revoke_token(self, token, request, session: AsyncSession):
            now = int(time.time())
            hint = request.form.get('token_type_hint')
            token.access_token_revoked_at = now
            if hint != 'access_token':
                token.refresh_token_revoked_at = now
            session.add(token)
            await session.commit()

    return _RevocationEndpoint


def create_bearer_token_validator(token_model):
    """Create a bearer token validator class with SQLAlchemy session
    and token model.

    :param token_model: Token model class
    """
    from ..rfc6750 import BearerTokenValidator

    class _BearerTokenValidator(BearerTokenValidator):
        async def authenticate_token(self, token_string, session: AsyncSession):
            q = select(token_model)
            return (await session.scalars(q.filter_by(access_token=token_string))).first()

        def request_invalid(self, request):
            return False

        def token_revoked(self, token):
            return token.revoked

    return _BearerTokenValidator
