from typing import TYPE_CHECKING, Any, Callable, Coroutine, Optional, Type

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from ..utils.functions import create_oauth_request
from .context import OAuthContext

if TYPE_CHECKING:
    from ..rfc6749.mixins import UserMixin
    from ..rfc6749.wrappers import OAuth2Request
    from .setting import OAuthSetting
    from .types import ContextDependency


class OAuthDependency(object):
    """
    OAuth Dependency for FastAPI
    """
    _config: Optional['OAuthSetting']

    def __init__(
        self,
        context_dependency: 'ContextDependency',
        request_cls: Type['OAuth2Request'],
    ):
        self.context_dependency = context_dependency
        self._request_cls = request_cls

    @property
    def get_oauth_context(self) -> Callable[..., Coroutine[Any, Any, OAuthContext]]:
        """
        Get OAuth Context Dependency for FastAPI
        :return:
        """
        get_db_session = self.context_dependency.get_db_session
        get_user_from_session = self.context_dependency.get_user_from_session
        get_user_from_token = self.context_dependency.get_user_from_token

        async def build_oauth_context(
            request: Request,
            session: AsyncSession = Depends(get_db_session),
            user_from_session: Optional['UserMixin'] = Depends(get_user_from_session),
            user_from_token: Optional['UserMixin'] = Depends(get_user_from_token),
        ) -> OAuthContext:
            allow_insecure_transport = False
            if self._config:
                allow_insecure_transport = self._config.OAUTH2_ALLOW_INSECURE_TRANSPORT

            oauth_request = await create_oauth_request(
                request=request,
                request_cls=self._request_cls,
                allow_insecure_transport=allow_insecure_transport,
            )
            return OAuthContext(
                request=oauth_request,
                session=session,
                user_from_token=user_from_token,
                user_from_session=user_from_session,
            )

        return build_oauth_context
