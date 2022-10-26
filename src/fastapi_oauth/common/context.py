from dataclasses import dataclass
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from ..rfc6749.mixins import UserMixin
from ..rfc6749.wrappers import OAuth2Request
from .errors import OAuth2Error


@dataclass
class OAuthContext:
    # OAuth Request
    request: OAuth2Request

    # Async SQLAlchemy session
    session: Optional[AsyncSession]

    # User extract from cookies session
    user_from_session: Optional[UserMixin]

    # User extract from token
    user_from_token: Optional[UserMixin]

    def verify_session(self):
        if self.session is None:
            raise OAuth2Error(
                'SQLAlchemy Session not found!',
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
