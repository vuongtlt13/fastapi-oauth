from collections.abc import Coroutine
from typing import Callable, Any, Dict

from sqlalchemy.ext.asyncio import AsyncSession

from fastapi_oauth.rfc6749 import OAuth2Request, ClientMixin, TokenMixin

QueryClientFn = Callable[[str, AsyncSession], Coroutine[Any, Any, ClientMixin]]
QueryTokenFn = Callable[[str, str, AsyncSession], Coroutine[Any, Any, TokenMixin]]
SaveTokenFn = Callable[[Dict, OAuth2Request, AsyncSession], Coroutine[Any, Any, Any]]

