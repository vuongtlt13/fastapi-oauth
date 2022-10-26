import sys
from typing import Any, Dict, List, Optional, Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from ..rfc6749.grants import BaseGrant
from ..rfc6749.mixins import ClientMixin, TokenMixin
from ..rfc6749.wrappers import OAuth2Request

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict


class QueryClientFn(Protocol):
    async def __call__(
        self,
        client_id: str,
        session: AsyncSession,
    ) -> Optional[ClientMixin]:
        ...


class QueryTokenFn(Protocol):
    async def __call__(
        self,
        token: str,
        token_type_hint: str,
        session: AsyncSession,
    ) -> Optional[TokenMixin]:
        ...


class SaveTokenFn(Protocol):
    async def __call__(
        self,
        token: Dict,
        request: OAuth2Request,
        session: AsyncSession,
    ) -> Any:
        ...


class AuthenticateClientFn(Protocol):
    async def __call__(
        self,
        query_client: QueryClientFn,
        request: OAuth2Request,
        session: AsyncSession,
    ) -> Optional[ClientMixin]:
        ...


class SingleTokenGenerator(Protocol):
    def __call__(
        self,
        grant_type: str,
        client: ClientMixin,
        user=None,
        scope=None,
        expires_in: int = None,
        include_refresh_token: bool = True,
    ) -> str:
        ...


class GroupTokenGenerator(Protocol):
    def __call__(
        self,
        grant_type: str,
        client: ClientMixin,
        user=None,
        scope=None,
        expires_in: int = None,
        include_refresh_token: bool = True,
    ) -> Dict:
        ...


class ExpireTokenGenerator(Protocol):
    def __call__(
        self,
        client: ClientMixin,
        grant_type: str,
    ) -> Dict:
        ...


class GrantExtension(object):
    def __call__(self, grant: BaseGrant):
        raise NotImplementedError()


ClientMetadataDict = TypedDict(
    'ClientMetadataDict',
    {
        'token_endpoint_auth_method': str,
        'redirect_uris': List[str],
        'grant_types': List[str],
        'response_types': List[str],
        'contacts': List[str],
        'client_name': str,
        'client_uri': str,
        'logo_uri': str,
        'scope': str,
        'tos_uri': str,
        'policy_uri': str,
        'jwks_uri': str,
        'jwks': List[str],
        'software_id': str,
        'software_version': str,
    },
    total=False,

)

OAuth2RequestDataPayloadDict = TypedDict(
    'OAuth2RequestDataPayloadDict',
    {
        'client_id': str,
        'client_secret': str,
        'response_type': str,
        'grant_type': str,
        'redirect_uri': str,
        'state': str,
        'token_type_hint': str,
        'scope': str,
    },
    total=False,
)
