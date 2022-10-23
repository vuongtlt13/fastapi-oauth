from typing import Type

from .rfc6749 import OAuth2Request


async def create_oauth_request(request, request_cls: Type[OAuth2Request]):
    if isinstance(request, request_cls):
        return request

    oauth_request = request_cls(request)
    await oauth_request.prepare_data()
    return oauth_request
