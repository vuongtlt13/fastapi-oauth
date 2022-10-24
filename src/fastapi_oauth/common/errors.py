#: coding: utf-8
from typing import Dict, Tuple

from starlette import status

from ..consts import DEFAULT_JSON_HEADERS


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
        uri: str = None
    ):
        if error is not None:
            self.error: str = error

        if description is not None:
            self.description: str = description

        if uri is not None:
            self.uri: str = uri

        message = '{}: {}'.format(self.error, self.description)
        super(BaseError, self).__init__(message)

    def __repr__(self):
        return '<{} "{}">'.format(self.__class__.__name__, self.error)


class HTTPError(BaseError):
    status_code: int = status.HTTP_400_BAD_REQUEST

    def __init__(
        self,
        error: str = None,
        description: str = None,
        uri: str = None,
        status_code: int = None,
    ):
        super(HTTPError, self).__init__(error, description, uri)
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
        return DEFAULT_JSON_HEADERS[:]

    def __call__(self, uri: str = None) -> Tuple[int, Dict, Dict]:
        self.uri = uri
        body = dict(self.get_body())
        headers = self.get_headers()
        return self.status_code, body, headers
