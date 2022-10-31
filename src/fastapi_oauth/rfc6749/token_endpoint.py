from typing import Any, Dict, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from ..common.context import OAuthContext
from .mixins import ClientMixin, TokenMixin
from .wrappers import OAuth2Request


class TokenEndpoint(object):
    #: Endpoint name to be registered
    ENDPOINT_NAME: str
    #: Supported token types
    SUPPORTED_TOKEN_TYPES = ('access_token', 'refresh_token')
    #: Allowed client authenticate methods
    CLIENT_AUTH_METHODS = ['client_secret_basic']

    def __init__(self, server):
        self.server = server

    async def authenticate_endpoint_client(self, request: OAuth2Request) -> ClientMixin:
        """Authentication client for endpoint with ``CLIENT_AUTH_METHODS``.
        """
        client = await self.server.authenticate_client(
            request=request,
            methods=self.CLIENT_AUTH_METHODS,
            endpoint=self.ENDPOINT_NAME,
        )
        request.client = client
        return client

    async def authenticate_token(self, context: OAuthContext, client: ClientMixin) -> Optional[TokenMixin]:
        raise NotImplementedError()

    async def create_endpoint_response(self, context: OAuthContext) -> Tuple[int, Any, Dict]:
        raise NotImplementedError()
