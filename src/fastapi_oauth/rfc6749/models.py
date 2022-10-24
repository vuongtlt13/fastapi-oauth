"""
    This module defines how to construct Client, AuthorizationCode and Token.
"""
import secrets
import time
from typing import Any, Dict, List, Optional, Text

from inflection import pluralize, underscore
from sqlalchemy import Column, DateTime, Integer, String, func
from sqlalchemy.orm import as_declarative, declared_attr

from ..common.encoding import json_dumps, json_loads
from .util import list_to_scope, scope_to_list


@as_declarative()
class Base:
    id: Any
    __name__: str

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
        super().__init__()

    # Generate __tablename__ automatically
    @declared_attr
    def __tablename__(self) -> str:
        return underscore(pluralize(self.__name__))

    @declared_attr
    def created_at(self):
        return Column(
            DateTime(timezone=True),
            server_default=func.now(), default=func.now(),
            nullable=False,
        )

    @declared_attr
    def updated_at(self):
        return Column(
            DateTime(timezone=True), server_default=func.now(),
            default=func.now(), nullable=False, onupdate=func.now(),
        )


class ClientMixin(object):
    """Implementation of OAuth 2 Client described in `Section 2`_ with
    some methods to help validation. A client has at least these information:

    * client_id: A string represents client identifier.
    * client_secret: A string represents client password.
    * token_endpoint_auth_method: A way to authenticate client at token
                                  endpoint.

    .. _`Section 2`: https://tools.ietf.org/html/rfc6749#section-2
    """

    def get_client_id(self):
        """A method to return client_id of the client. For instance, the value
        in database is saved in a column called ``client_id``::

            def get_client_id(self):
                return self.client_id

        :return: string
        """
        raise NotImplementedError()

    def get_default_redirect_uri(self):
        """A method to get client default redirect_uri. For instance, the
        database table for client has a column called ``default_redirect_uri``::

            def get_default_redirect_uri(self):
                return self.default_redirect_uri

        :return: A URL string
        """
        raise NotImplementedError()

    def get_allowed_scope(self, scope):
        """A method to return a list of requested scopes which are supported by
        this client. For instance, there is a ``scope`` column::

            def get_allowed_scope(self, scope):
                if not scope:
                    return ''
                allowed = set(scope_to_list(self.scope))
                return list_to_scope([s for s in scope.split() if s in allowed])

        :param scope: the requested scope.
        :return: string of scope
        """
        raise NotImplementedError()

    def check_redirect_uri(self, redirect_uri):
        """Validate redirect_uri parameter in Authorization Endpoints. For
        instance, in the client table, there is an ``allowed_redirect_uris``
        column::

            def check_redirect_uri(self, redirect_uri):
                return redirect_uri in self.allowed_redirect_uris

        :param redirect_uri: A URL string for redirecting.
        :return: bool
        """
        raise NotImplementedError()

    def check_client_secret(self, client_secret):
        """Check client_secret matching with the client. For instance, in
        the client table, the column is called ``client_secret``::

            import secrets

            def check_client_secret(self, client_secret):
                return secrets.compare_digest(self.client_secret, client_secret)

        :param client_secret: A string of client secret
        :return: bool
        """
        raise NotImplementedError()

    def check_endpoint_auth_method(self, method, endpoint):
        """Check if client support the given method for the given endpoint.
        There is a ``token_endpoint_auth_method`` defined via `RFC7591`_.
        Developers MAY re-implement this method with::

            def check_endpoint_auth_method(self, method, endpoint):
                if endpoint == 'token':
                    # if client table has ``token_endpoint_auth_method``
                    return self.token_endpoint_auth_method == method
                return True

        Method values defined by this specification are:

        *  "none": The client is a public client as defined in OAuth 2.0,
            and does not have a client secret.

        *  "client_secret_post": The client uses the HTTP POST parameters
            as defined in OAuth 2.0

        *  "client_secret_basic": The client uses HTTP Basic as defined in
            OAuth 2.0

        .. _`RFC7591`: https://tools.ietf.org/html/rfc7591
        """
        raise NotImplementedError()

    def check_response_type(self, response_type):
        """Validate if the client can handle the given response_type. There
        are two response types defined by RFC6749: code and token. For
        instance, there is a ``allowed_response_types`` column in your client::

            def check_response_type(self, response_type):
                return response_type in self.response_types

        :param response_type: the requested response_type string.
        :return: bool
        """
        raise NotImplementedError()

    def check_grant_type(self, grant_type):
        """Validate if the client can handle the given grant_type. There are
        four grant types defined by RFC6749:

        * authorization_code
        * implicit
        * client_credentials
        * password

        For instance, there is a ``allowed_grant_types`` column in your client::

            def check_grant_type(self, grant_type):
                return grant_type in self.grant_types

        :param grant_type: the requested grant_type string.
        :return: bool
        """
        raise NotImplementedError()


class OAuth2ClientBase(Base, ClientMixin):
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
    def client_metadata(self) -> Dict:
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
    def client_name(self) -> str:
        return self.client_metadata.get('client_name')

    @property
    def client_uri(self) -> str:
        return self.client_metadata.get('client_uri')

    @property
    def logo_uri(self) -> str:
        return self.client_metadata.get('logo_uri')

    @property
    def scope(self) -> str:
        return self.client_metadata.get('scope', '')

    @property
    def contacts(self) -> List[str]:
        return self.client_metadata.get('contacts', [])

    @property
    def tos_uri(self) -> str:
        return self.client_metadata.get('tos_uri')

    @property
    def policy_uri(self) -> str:
        return self.client_metadata.get('policy_uri')

    @property
    def jwks_uri(self) -> str:
        return self.client_metadata.get('jwks_uri')

    @property
    def jwks(self) -> List:
        return self.client_metadata.get('jwks', [])

    @property
    def software_id(self) -> Any:
        return self.client_metadata.get('software_id')

    @property
    def software_version(self) -> str:
        return self.client_metadata.get('software_version')

    def get_client_id(self) -> str:
        return self.client_id

    def get_default_redirect_uri(self) -> Optional[str]:
        if self.redirect_uris:
            return self.redirect_uris[0]

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


class AuthorizationCodeMixin(object):
    def get_redirect_uri(self):
        """A method to get authorization code's ``redirect_uri``.
        For instance, the database table for authorization code has a
        column called ``redirect_uri``::

            def get_redirect_uri(self):
                return self.redirect_uri

        :return: A URL string
        """
        raise NotImplementedError()

    def get_scope(self):
        """A method to get scope of the authorization code. For instance,
        the column is called ``scope``::

            def get_scope(self):
                return self.scope

        :return: scope string
        """
        raise NotImplementedError()


class OAuth2AuthorizationCodeBase(Base, AuthorizationCodeMixin):
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


class TokenMixin(object):
    def check_client(self, client):
        """A method to check if this token is issued to the given client.
        For instance, ``client_id`` is saved on token table::

            def check_client(self, client):
                return self.client_id == client.client_id

        :return: bool
        """
        raise NotImplementedError()

    def get_scope(self):
        """A method to get scope of the authorization code. For instance,
        the column is called ``scope``::

            def get_scope(self):
                return self.scope

        :return: scope string
        """
        raise NotImplementedError()

    def get_expires_in(self):
        """A method to get the ``expires_in`` value of the token. e.g.
        the column is called ``expires_in``::

            def get_expires_in(self):
                return self.expires_in

        :return: timestamp int
        """
        raise NotImplementedError()

    def is_expired(self):
        """A method to define if this token is expired. For instance,
        there is a column ``expired_at`` in the table::

            def is_expired(self):
                return self.expired_at < now

        :return: boolean
        """
        raise NotImplementedError()

    def is_revoked(self):
        """A method to define if this token is revoked. For instance,
        there is a boolean column ``revoked`` in the table::

            def is_revoked(self):
                return self.revoked

        :return: boolean
        """
        return NotImplementedError()


class OAuth2TokenBase(Base, TokenMixin):
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

    def check_client(self, client):
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
