from typing import Any, Callable, Coroutine, Dict, Optional, Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from fastapi_oauth.rfc6749.models import ClientMixin, TokenMixin
from fastapi_oauth.rfc6749.wrappers import OAuth2Request

QueryClientFn = Callable[[str, AsyncSession], Coroutine[Any, Any, ClientMixin]]
QueryTokenFn = Callable[[str, str, AsyncSession], Coroutine[Any, Any, TokenMixin]]
SaveTokenFn = Callable[[Dict, OAuth2Request, AsyncSession], Coroutine[Any, Any, Any]]
AuthenticateClientFn = Callable[[QueryClientFn, OAuth2Request, AsyncSession], Coroutine[Any, Any, ClientMixin]]

TokenGenerator = Callable[[str, ClientMixin, Any, Any, Optional[int], bool], Dict]
