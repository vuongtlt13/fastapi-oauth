#: coding: utf-8
from typing import Dict, Tuple

from starlette import status

from ..utils.consts import DEFAULT_JSON_HEADERS
from .urls import add_params_to_uri


class BaseError(Exception):
    """Base Exception for all errors in library."""

    #: short-string error code
    error = None
    #: long-string to describe this error
    description = ''
    #: web page that describes this error
    uri = None

    def __init__(
        self,
        error: str = None,
        description: str = '',
        uri: str = None,
    ):
        if error is not None:
            self.error = error

        if description is not None:
            self.description = description

        if uri is not None:
            self.uri = uri

        message = '{}: {}'.format(self.error, self.description)
        super().__init__(message)

    def __repr__(self):
        return '<{} "{}">'.format(self.__class__.__name__, self.error)


class HTTPError(BaseError):
    status_code: int = status.HTTP_400_BAD_REQUEST

    def __init__(
        self,
        error: str = None,
        description: str = '',
        uri: str = None,
        status_code: int = None,
    ):
        super().__init__(error, description, uri)
        if status_code is not None:
            self.status_code = status_code

    def get_error_description(self):
        return self.description

    def get_body(self):
        error = [('error', self.error)]

        if self.description:
            error.append(('error_description', self.description))

        if self.uri:
            error.append(('error_uri', self.uri))
        return error

    def get_headers(self) -> Dict:
        return DEFAULT_JSON_HEADERS

    def __call__(self, uri: str = None) -> Tuple[int, Dict, Dict]:
        self.uri = uri
        body = dict(self.get_body())
        headers = self.get_headers()
        return self.status_code, body, headers


class OAuth2Error(HTTPError):
    def __init__(
        self, description=None, uri=None,
        status_code=None, state=None,
        redirect_uri=None, redirect_fragment=False, error=None,
    ):
        super().__init__(error, description, uri, status_code)
        self.state = state
        self.redirect_uri = redirect_uri
        self.redirect_fragment = redirect_fragment

    def get_body(self):
        """Get a list of body."""
        error = super(OAuth2Error, self).get_body()
        if self.state:
            error.append(('state', self.state))
        return error

    def __call__(self, uri=None):
        if self.redirect_uri:
            params = self.get_body()
            loc = add_params_to_uri(self.redirect_uri, params, self.redirect_fragment)
            return 302, '', [('Location', loc)]
        return super().__call__(uri=uri)


class SessionOAuthContextError(OAuth2Error):
    error = 'database_session_not_found'
    description = 'Database session not found!'
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR


class MissingQueryClientError(OAuth2Error):
    error = 'database_session_not_found'
    description = 'Database session not found!'
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR


class UnsetQueryTokenError(OAuth2Error):
    error = 'unset_query_token'
    description = 'Function query_token is not set! query_token function can be set by calling init_app function!'
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR


class UnsetSaveTokenError(OAuth2Error):
    error = 'unset_save_token'
    description = 'Function save_token is not set! save_token function can be set by calling init_app function!'
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR


class UnsetQueryClientError(OAuth2Error):
    error = 'unset_query_client'
    description = 'Function query_client is not set! query_client function can be set by calling init_app function!'
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
