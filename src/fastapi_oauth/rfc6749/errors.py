"""
    Implementation for OAuth 2 Error Response.
    https://tools.ietf.org/html/rfc6749#section-5.2

    :copyright: (c) 2022 by Do Quoc Vuong.
"""
from fastapi import status

__all__ = [
    'InsecureTransportError', 'InvalidRequestError',
    'InvalidClientError', 'UnauthorizedClientError', 'InvalidGrantError',
    'UnsupportedResponseTypeError', 'UnsupportedGrantTypeError',
    'InvalidScopeError', 'AccessDeniedError',
    'MissingAuthorizationError', 'UnsupportedTokenTypeError',
    'MissingCodeException', 'MissingTokenException',
    'MissingTokenTypeException', 'MismatchingStateException',
]

from ..common.errors import OAuth2Error


class InsecureTransportError(OAuth2Error):
    error = 'insecure_transport'
    description = 'OAuth 2 MUST utilize https.'


class InvalidRequestError(OAuth2Error):
    """The request is missing a required parameter, includes an
    unsupported parameter value (other than grant type),
    repeats a parameter, includes multiple credentials,
    utilizes more than one mechanism for authenticating the
    client, or is otherwise malformed.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error = 'invalid_request'


class InvalidClientError(OAuth2Error):
    """Client authentication failed (e.g., unknown client, no
    client authentication included, or unsupported
    authentication method).  The authorization server MAY
    return an HTTP 401 (Unauthorized) status code to indicate
    which HTTP authentication schemes are supported.  If the
    client attempted to authenticate via the "Authorization"
    request header field, the authorization server MUST
    respond with an HTTP 401 (Unauthorized) status code and
    include the "WWW-Authenticate" response header field
    matching the authentication scheme used by the client.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error = 'invalid_client'
    description = 'Client not found!'
    status_code = status.HTTP_400_BAD_REQUEST

    def get_headers(self):
        headers = super().get_headers()
        if self.status_code == status.HTTP_401_UNAUTHORIZED:
            error_description = self.get_error_description()
            # safe escape
            error_description = error_description.replace('"', '|')
            extras = [
                'error="{}"'.format(self.error),
                'error_description="{}"'.format(error_description),
            ]
            headers['WWW-Authenticate'] = 'Basic ' + ', '.join(extras)
        return headers


class InvalidGrantError(OAuth2Error):
    """The provided authorization grant (e.g., authorization
    code, resource owner credentials) or refresh token is
    invalid, expired, revoked, does not match the redirection
    URI used in the authorization request, or was issued to
    another client.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error = 'invalid_grant'


class UnauthorizedClientError(OAuth2Error):
    """ The authenticated client is not authorized to use this
    authorization grant type.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error = 'unauthorized_client'
    description = 'Unauthorized Client'


class UnsupportedResponseTypeError(OAuth2Error):
    """The authorization server does not support obtaining
    an access token using this method."""
    error = 'unsupported_response_type'
    description = 'Unsupported Response Type'

    def __init__(self, response_type):
        super(UnsupportedResponseTypeError, self).__init__()
        self.response_type = response_type

    def get_error_description(self):
        return f'response_type={self.response_type} is not supported'


class UnsupportedGrantTypeError(OAuth2Error):
    """The authorization grant type is not supported by the
    authorization server.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error = 'unsupported_grant_type'
    description = 'Unsupported Grant Type'

    def __init__(self, grant_type):
        super(UnsupportedGrantTypeError, self).__init__()
        self.grant_type = grant_type

    def get_error_description(self):
        return f'grant_type={self.grant_type} is not supported'


class InvalidScopeError(OAuth2Error):
    """The requested scope is invalid, unknown, malformed, or
    exceeds the scope granted by the resource owner.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error = 'invalid_scope'
    description = 'The requested scope is invalid, unknown, or malformed.'


class AccessDeniedError(OAuth2Error):
    """The resource owner or authorization server denied the request.

    Used in authorization endpoint for "code" and "implicit". Defined in
    `Section 4.1.2.1`_.

    .. _`Section 4.1.2.1`: https://tools.ietf.org/html/rfc6749#section-4.1.2.1
    """
    error = 'access_denied'
    description = 'The resource owner or authorization server denied the request'


class ForbiddenError(OAuth2Error):
    status_code = status.HTTP_401_UNAUTHORIZED

    def __init__(self, auth_type=None, realm=None):
        super(ForbiddenError, self).__init__()
        self.auth_type = auth_type
        self.realm = realm

    def get_headers(self):
        headers = super(ForbiddenError, self).get_headers()
        if not self.auth_type:
            return headers

        extras = []
        if self.realm:
            extras.append('realm="{}"'.format(self.realm))
        extras.append('error="{}"'.format(self.error))
        error_description = self.description
        extras.append('error_description="{}"'.format(error_description))
        headers['WWW-Authenticate'] = f'{self.auth_type} ' + ', '.join(extras)
        return headers


class MissingAuthorizationError(ForbiddenError):
    error = 'missing_authorization'
    description = 'Missing "Authorization" in headers.'


class UnsupportedTokenTypeError(ForbiddenError):
    error = 'unsupported_token_type'
    description = 'Unsupported Token Type'


class MissingCodeException(OAuth2Error):
    error = 'missing_code'
    description = 'Missing "code" in response.'


class MissingTokenException(OAuth2Error):
    error = 'missing_token'
    description = 'Missing "access_token" in response.'


class MissingTokenTypeException(OAuth2Error):
    error = 'missing_token_type'
    description = 'Missing "token_type" in response.'


class MismatchingStateException(OAuth2Error):
    error = 'mismatching_state'
    description = 'CSRF Warning! State not equal in request and response.'
