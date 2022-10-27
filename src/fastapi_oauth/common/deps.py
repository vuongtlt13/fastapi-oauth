from typing import Optional, Type, TYPE_CHECKING

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from .context import OAuthContext
from ..utils.functions import create_oauth_request

if TYPE_CHECKING:
    from ..rfc6749.mixins import UserMixin
    from ..rfc6749.wrappers import OAuth2Request
    from .types import ContextDependency


class OAuthDependency(object):
    """
    OAuth Dependency for FastAPI
    """

    def __init__(
        self,
        context_dependency: "ContextDependency",
        request_cls: Type["OAuth2Request"],
    ):
        self.context_dependency = context_dependency
        self._request_cls = request_cls

    async def get_oauth_context(
        self,
        request: Request,
        request_cls: Type["OAuth2Request"] = None,
    ) -> OAuthContext:
        """
        Get OAuth Context Dependency for FastAPI
        :param request_cls: OAuth2Request class
        :param request: starlette request instance
        :return:
        """
        get_db_session = self.context_dependency.get_db_session
        get_user_from_session = self.context_dependency.get_user_from_session
        get_user_from_token = self.context_dependency.get_user_from_token

        async def build_oauth_context(
            session: AsyncSession = Depends(get_db_session),
            user_from_session: Optional["UserMixin"] = Depends(get_user_from_session),
            user_from_token: Optional["UserMixin"] = Depends(get_user_from_token),
        ) -> OAuthContext:
            oauth_request = await create_oauth_request(
                request=request,
                request_cls=request_cls or self._request_cls,
            )
            return OAuthContext(
                request=oauth_request,
                session=session,
                user_from_token=user_from_token,
                user_from_session=user_from_session,
            )

        return await build_oauth_context()
