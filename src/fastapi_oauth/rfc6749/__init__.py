# -*- coding: utf-8 -*-
"""
    This module represents a direct implementation of
    The OAuth 2.0 Authorization Framework.

    https://tools.ietf.org/html/rfc6749
"""

from .authenticate_client import ClientAuthentication
from .authorization_server import AuthorizationServer
from .errors import (  # exceptions for clients
    AccessDeniedError,
    InsecureTransportError,
    InvalidClientError,
    InvalidGrantError,
    InvalidRequestError,
    InvalidScopeError,
    MismatchingStateException,
    MissingAuthorizationError,
    MissingCodeException,
    MissingTokenException,
    MissingTokenTypeException,
    OAuth2Error,
    UnauthorizedClientError,
    UnsupportedGrantTypeError,
    UnsupportedResponseTypeError,
    UnsupportedTokenTypeError,
)
from .grants import (
    AuthorizationCodeGrant,
    AuthorizationEndpointMixin,
    BaseGrant,
    ClientCredentialsGrant,
    ImplicitGrant,
    RefreshTokenGrant,
    ResourceOwnerPasswordCredentialsGrant,
    TokenEndpointMixin,
)
from .models import AuthorizationCodeMixin, ClientMixin, TokenMixin
from .resource_protector import ResourceProtector, TokenValidator
from .token_endpoint import TokenEndpoint
from .util import list_to_scope, scope_to_list
from .wrappers import HttpRequest, OAuth2Request, OAuth2Token

__all__ = [
    'OAuth2Request', 'OAuth2Token', 'HttpRequest',
    'OAuth2Error',
    'AccessDeniedError',
    'MissingAuthorizationError',
    'InvalidGrantError',
    'InvalidClientError',
    'InvalidRequestError',
    'InvalidScopeError',
    'InsecureTransportError',
    'UnauthorizedClientError',
    'UnsupportedResponseTypeError',
    'UnsupportedGrantTypeError',
    'UnsupportedTokenTypeError',
    'MissingCodeException',
    'MissingTokenException',
    'MissingTokenTypeException',
    'MismatchingStateException',
    'ClientMixin', 'AuthorizationCodeMixin', 'TokenMixin',
    'ClientAuthentication',
    'AuthorizationServer',
    'ResourceProtector',
    'TokenValidator',
    'TokenEndpoint',
    'BaseGrant',
    'AuthorizationEndpointMixin',
    'TokenEndpointMixin',
    'AuthorizationCodeGrant',
    'ImplicitGrant',
    'ResourceOwnerPasswordCredentialsGrant',
    'ClientCredentialsGrant',
    'RefreshTokenGrant',
    'scope_to_list', 'list_to_scope',
]
