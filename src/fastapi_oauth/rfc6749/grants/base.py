from typing import TYPE_CHECKING, Union

from sqlalchemy.ext.asyncio import AsyncSession

from ...consts import DEFAULT_JSON_HEADERS
from ..errors import InvalidRequestError

if TYPE_CHECKING:
    from ..authorization_server import AuthorizationServer


class BaseGrant(object):
    #: Allowed client auth methods for token endpoint
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic']

    #: Designed for which "grant_type"
    GRANT_TYPE = None

    # NOTE: there is no charset for application/json, since
    # application/json should always in UTF-8.
    # The example on RFC is incorrect.
    # https://tools.ietf.org/html/rfc4627
    TOKEN_RESPONSE_HEADER = DEFAULT_JSON_HEADERS

    def __init__(self, request, server: 'AuthorizationServer'):
        self.prompt = None
        self.redirect_uri = None
        self.request = request
        self.server: 'AuthorizationServer' = server
        self._hooks = {
            'after_validate_authorization_request': set(),
            'after_validate_consent_request': set(),
            'after_validate_token_request': set(),
            'process_token': set(),
        }

    @property
    def client(self):
        return self.request.client

    def generate_token(
        self, user=None, scope=None, grant_type=None,
        expires_in=None, include_refresh_token=True,
    ):
        if grant_type is None:
            grant_type = self.GRANT_TYPE
        return self.server.generate_token(
            client=self.request.client,
            grant_type=grant_type,
            user=user,
            scope=scope,
            expires_in=expires_in,
            include_refresh_token=include_refresh_token,
        )

    def authenticate_token_endpoint_client(self):
        """Authenticate client with the given methods for token endpoint.

        For example, the client makes the following HTTP request using TLS:

        .. code-block:: http

            POST /token HTTP/1.1
            Host: server.example.com
            Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
            Content-Type: application/x-www-form-urlencoded

            grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
            &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb

        Default available methods are: "none", "client_secret_basic" and
        "client_secret_post".

        :return: client
        """
        client = self.server.authenticate_client(
            self.request, self.TOKEN_ENDPOINT_AUTH_METHODS,
        )
        self.server.send_signal(
            'after_authenticate_client',
            client=client, grant=self,
        )
        return client

    async def save_token(self, token, session: AsyncSession):
        """A method to save token into database."""
        return await self.server.save_token(token, self.request, session)

    def validate_requested_scope(self):
        """Validate if requested scope is supported by Authorization Server."""
        scope = self.request.scope
        state = self.request.state
        return self.server.validate_requested_scope(scope, state)

    def register_hook(self, hook_type, hook):
        if hook_type not in self._hooks:
            raise ValueError(
                'Hook type %s is not in %s.',
                hook_type, self._hooks,
            )
        self._hooks[hook_type].add(hook)

    def execute_hook(self, hook_type, *args, **kwargs):
        for hook in self._hooks[hook_type]:
            hook(self, *args, **kwargs)


class TokenEndpointMixin(object):
    #: Allowed HTTP methods of this token endpoint
    TOKEN_ENDPOINT_HTTP_METHODS = ['POST']

    #: Designed for which "grant_type"
    GRANT_TYPE = None

    @classmethod
    def check_token_endpoint(cls, request):
        return request.grant_type == cls.GRANT_TYPE and \
               request.method in cls.TOKEN_ENDPOINT_HTTP_METHODS

    async def validate_token_request(self, session: AsyncSession):
        raise NotImplementedError()

    async def create_token_response(self, session: AsyncSession):
        raise NotImplementedError()


class AuthorizationEndpointMixin(object):
    RESPONSE_TYPES = set()
    ERROR_RESPONSE_FRAGMENT = False

    @classmethod
    def check_authorization_endpoint(cls, request):
        return request.response_type in cls.RESPONSE_TYPES

    @staticmethod
    def validate_authorization_redirect_uri(request, client) -> str:
        if request.redirect_uri:
            if not client.check_redirect_uri(request.redirect_uri):
                raise InvalidRequestError(
                    f'Redirect URI {request.redirect_uri} is not supported by client.',
                    state=request.state,
                )
            return request.redirect_uri
        else:
            redirect_uri = client.get_default_redirect_uri()
            if not redirect_uri:
                raise InvalidRequestError(
                    'Missing "redirect_uri" in request.',
                    state=request.state,
                )
            return redirect_uri

    def validate_consent_request(self: Union[BaseGrant, 'AuthorizationEndpointMixin'], session: AsyncSession):
        redirect_uri = await self.validate_authorization_request(session)
        self.execute_hook('after_validate_consent_request', redirect_uri)
        # noinspection PyAttributeOutsideInit
        self.redirect_uri = redirect_uri

    async def validate_authorization_request(self, session: AsyncSession):
        raise NotImplementedError()

    async def create_authorization_response(self, redirect_uri: str, grant_user, session: AsyncSession):
        raise NotImplementedError()
