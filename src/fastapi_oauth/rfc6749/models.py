"""
    This module defines how to construct Client, AuthorizationCode and Token.
"""
import secrets
import time
from typing import Any, List, Optional

from sqlalchemy import Column, Integer, String, Text

from ..common.encoding import json_dumps, json_loads
from ..common.types import ClientMetadataDict
from .mixins import AuthorizationCodeMixin, ClientMixin, TokenMixin
from .util import list_to_scope, scope_to_list


class OAuth2ClientBase(ClientMixin):
    client_id = Column(String(48), index=True)
    client_secret = Column(String(120))
    client_id_issued_at = Column(Integer, nullable=False, default=0)
    client_secret_expires_at = Column(Integer, nullable=False, default=0)
    _client_metadata = Column('client_metadata', Text)

    @property
    def client_info(self):
        """Implementation for Client Info in OAuth 2.0 Dynamic Client
        Registration Protocol via `Section 3.2.1`_.

        .. _`Section 3.2.1`: https://tools.ietf.org/html/rfc7591#section-3.2.1
        """
        return dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            client_id_issued_at=self.client_id_issued_at,
            client_secret_expires_at=self.client_secret_expires_at,
        )

    @property
    def client_metadata(self) -> ClientMetadataDict:
        if 'client_metadata' in self.__dict__:
            return self.__dict__['client_metadata']
        if self._client_metadata:
            data = json_loads(self._client_metadata)
            self.__dict__['client_metadata'] = data
            return data
        return {}

    def set_client_metadata(self, value):
        self._client_metadata = json_dumps(value)

    @property
    def redirect_uris(self) -> List[str]:
        return self.client_metadata.get('redirect_uris', [])

    @property
    def token_endpoint_auth_method(self) -> str:
        return self.client_metadata.get(
            'token_endpoint_auth_method',
            'client_secret_basic',
        )

    @property
    def grant_types(self) -> List[str]:
        return self.client_metadata.get('grant_types', [])

    @property
    def response_types(self) -> List[str]:
        return self.client_metadata.get('response_types', [])

    @property
    def client_name(self) -> Optional[str]:
        return self.client_metadata.get('client_name', None)

    @property
    def client_uri(self) -> Optional[str]:
        return self.client_metadata.get('client_uri', None)

    @property
    def logo_uri(self) -> Optional[str]:
        return self.client_metadata.get('logo_uri', None)

    @property
    def scope(self) -> str:
        return self.client_metadata.get('scope', '')

    @property
    def contacts(self) -> List[str]:
        return self.client_metadata.get('contacts', [])

    @property
    def tos_uri(self) -> Optional[str]:
        return self.client_metadata.get('tos_uri', None)

    @property
    def policy_uri(self) -> Optional[str]:
        return self.client_metadata.get('policy_uri', None)

    @property
    def jwks_uri(self) -> Optional[str]:
        return self.client_metadata.get('jwks_uri', None)

    @property
    def jwks(self) -> List[str]:
        return self.client_metadata.get('jwks', [])

    @property
    def software_id(self) -> Any:
        return self.client_metadata.get('software_id', None)

    @property
    def software_version(self) -> Optional[str]:
        return self.client_metadata.get('software_version', None)

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self) -> Optional[str]:
        if self.redirect_uris:
            return self.redirect_uris[0]
        return None

    def get_allowed_scope(self, scope) -> str:
        if not scope:
            return ''
        allowed = set(self.scope.split())
        scopes = scope_to_list(scope)
        return list_to_scope([s for s in scopes if s in allowed])

    def check_redirect_uri(self, redirect_uri) -> bool:
        return redirect_uri in self.redirect_uris

    def has_client_secret(self):
        return bool(self.client_secret)

    def check_client_secret(self, client_secret):
        return secrets.compare_digest(self.client_secret, client_secret)

    def check_endpoint_auth_method(self, method, endpoint):
        if endpoint == 'token':
            return self.token_endpoint_auth_method == method
        # TODO
        return True

    def check_response_type(self, response_type: str):
        return response_type in self.response_types

    def check_grant_type(self, grant_type: str):
        return grant_type in self.grant_types


class OAuth2AuthorizationCodeBase(AuthorizationCodeMixin):
    code = Column(String(120), unique=True, nullable=False)
    client_id = Column(String(48))
    redirect_uri = Column(Text, default='')
    response_type = Column(Text, default='')
    scope = Column(Text, default='')
    nonce = Column(Text)
    auth_time = Column(
        Integer, nullable=False,
        default=lambda: int(time.time()),
    )

    code_challenge = Column(Text)
    code_challenge_method = Column(String(48))

    def is_expired(self):
        return self.auth_time + 300 < time.time()

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope

    def get_auth_time(self):
        return self.auth_time

    def get_nonce(self):
        return self.nonce


class OAuth2TokenBase(TokenMixin):
    client_id = Column(String(48))
    token_type = Column(String(40))
    access_token = Column(String(255), unique=True, nullable=False)
    refresh_token = Column(String(255), index=True)
    scope = Column(Text, default='')
    issued_at = Column(
        Integer, nullable=False, default=lambda: int(time.time()),
    )
    access_token_revoked_at = Column(Integer, nullable=False, default=0)
    refresh_token_revoked_at = Column(Integer, nullable=False, default=0)
    expires_in = Column(Integer, nullable=False, default=0)

    def check_client(self, client: ClientMixin) -> bool:
        return self.client_id == client.get_client_id()

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def is_revoked(self):
        return self.access_token_revoked_at or self.refresh_token_revoked_at

    def is_expired(self):
        if not self.expires_in:
            return False

        expires_at = self.issued_at + self.expires_in
        return expires_at < time.time()


__all__ = [
    'OAuth2ClientBase',
    'OAuth2AuthorizationCodeBase',
    'OAuth2TokenBase',
]
