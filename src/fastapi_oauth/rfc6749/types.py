from typing import Any, Callable, Coroutine, Dict

from sqlalchemy.ext.asyncio import AsyncSession

from .models import ClientMixin, TokenMixin
from .wrappers import OAuth2Request

QueryClientFn = Callable[[str, AsyncSession], Coroutine[Any, Any, ClientMixin]]
QueryTokenFn = Callable[[str, str, AsyncSession], Coroutine[Any, Any, TokenMixin]]
SaveTokenFn = Callable[[Dict, OAuth2Request, AsyncSession], Coroutine[Any, Any, Any]]
AuthenticateClientFn = Callable[[QueryClientFn, OAuth2Request, AsyncSession], Coroutine[Any, Any, ClientMixin]]
