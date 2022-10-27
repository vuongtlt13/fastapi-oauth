from dataclasses import dataclass
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..rfc6749.mixins import TokenMixin, UserMixin
from ..rfc6749.wrappers import OAuth2Request


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

    # Info after validate through token validator
    token: Optional[TokenMixin] = None
