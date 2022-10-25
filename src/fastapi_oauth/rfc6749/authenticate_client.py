"""
    Registry of client authentication methods, with 3 built-in methods:

    1. client_secret_basic
    2. client_secret_post
    3. none

    The "client_secret_basic" method is used a lot in examples of `RFC6749`_,
    but the concept of naming are introduced in `RFC7591`_.

    .. _`RFC6749`: https://tools.ietf.org/html/rfc6749
    .. _`RFC7591`: https://tools.ietf.org/html/rfc7591
"""

import logging
from typing import Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from ..common.types import AuthenticateClientFn, QueryClientFn
from .errors import InvalidClientError
from .mixins import ClientMixin
from .util import extract_basic_authorization
from .wrappers import OAuth2Request

log = logging.getLogger(__name__)


class ClientAuthentication(object):
    def __init__(self, query_client: QueryClientFn):
        self.query_client: QueryClientFn = query_client
        self._methods: Dict[str, AuthenticateClientFn] = {
            'none': authenticate_none,
            'client_secret_basic': authenticate_client_secret_basic,
            'client_secret_post': authenticate_client_secret_post,
        }

    def register(self, method: str, func: AuthenticateClientFn):
        self._methods[method] = func

    async def authenticate(
        self,
        request: OAuth2Request,
        methods: List[str],
        session: AsyncSession,
        endpoint='token',
    ) -> ClientMixin:
        for method in methods:
            func: AuthenticateClientFn = self._methods[method]
            client = await func(query_client=self.query_client, request=request, session=session)
            if client and client.check_endpoint_auth_method(method, endpoint):
                request.auth_method = method
                return client

        if 'client_secret_basic' in methods:
            raise InvalidClientError(state=request.state, status_code=401)
        raise InvalidClientError(state=request.state)


async def authenticate_client_secret_basic(
    query_client: QueryClientFn,
    request: OAuth2Request,
    session: AsyncSession,
) -> Optional[ClientMixin]:
    """Authenticate client by ``client_secret_basic`` method. The client
    uses HTTP Basic for authentication.
    """
    client_id, client_secret = extract_basic_authorization(dict(request.raw_request.headers))
    if client_id and client_secret:
        client = await _validate_client(
            query_client=query_client,
            client_id=client_id,
            state=request.state,
            session=session,
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
        if client.check_client_secret(client_secret):
            log.debug(f'Authenticate {client_id} via "client_secret_basic" success')
            return client
    log.debug(f'Authenticate {client_id} via "client_secret_basic" failed')
    return None


async def authenticate_client_secret_post(
    query_client: QueryClientFn,
    request: OAuth2Request,
    session: AsyncSession,
) -> Optional[ClientMixin]:
    """Authenticate client by ``client_secret_post`` method. The client
    uses POST parameters for authentication.
    """
    data = request.form
    client_id = data.get('client_id')
    client_secret = data.get('client_secret')
    if client_id and client_secret:
        client = await _validate_client(
            query_client=query_client,
            client_id=client_id,
            state=request.state,
            session=session,
        )
        if client.check_client_secret(client_secret):
            log.debug(f'Authenticate {client_id} via "client_secret_post" success')
            return client
    log.debug(f'Authenticate {client_id} via "client_secret_post" failed')
    return None


async def authenticate_none(
    query_client: QueryClientFn,
    request: OAuth2Request,
    session: AsyncSession,
) -> Optional[ClientMixin]:
    """Authenticate public client by ``none`` method. The client
    does not have a client secret.
    """
    client_id = request.client_id
    if client_id and not request.data.get('client_secret', None):
        client = await _validate_client(
            query_client=query_client,
            client_id=client_id,
            state=request.state,
            session=session,
        )
        log.debug(f'Authenticate {client_id} via "none" success')
        return client
    log.debug(f'Authenticate {client_id} via "none" failed')
    return None


async def _validate_client(
    query_client: QueryClientFn,
    client_id: str,
    session: AsyncSession,
    state: str = None,
    status_code: int = status.HTTP_400_BAD_REQUEST,
) -> ClientMixin:
    if client_id is None:
        raise InvalidClientError(state=state, status_code=status_code)

    client = await query_client(client_id=client_id, session=session)
    if not client:
        raise InvalidClientError(state=state, status_code=status_code)

    return client


__all__ = [
    'ClientAuthentication',
    'authenticate_none',
    'authenticate_client_secret_basic',
    'authenticate_client_secret_post',
]
