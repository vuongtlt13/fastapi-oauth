import sys
from typing import Any, Callable, Coroutine, Dict, List, Optional, TypeVar

from sqlalchemy.ext.asyncio import AsyncSession

from ..rfc6749.mixins import ClientMixin, TokenMixin
from ..rfc6749.wrappers import OAuth2Request

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

QueryClientFn = Callable[[str, AsyncSession], Coroutine[Any, Any, Optional[ClientMixin]]]
QueryTokenFn = Callable[[str, str, AsyncSession], Coroutine[Any, Any, Optional[TokenMixin]]]
SaveTokenFn = Callable[[Dict, OAuth2Request, AsyncSession], Coroutine[Any, Any, Any]]
AuthenticateClientFn = Callable[
    [QueryClientFn, OAuth2Request, AsyncSession], Coroutine[Any, Any, Optional[ClientMixin]],
]

TokenGenerator = Callable[[str, ClientMixin, Any, Any, Optional[int], bool], Dict]

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
