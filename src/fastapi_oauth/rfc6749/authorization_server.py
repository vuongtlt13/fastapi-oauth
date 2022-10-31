from typing import Any, Dict, List, Optional, Tuple, Type

from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from starlette.responses import Response

from ..common.errors import OAuth2Error
from ..common.setting import OAuthSetting
from ..common.types import AuthenticateClientFn, GroupTokenGenerator, QueryClientFn, SaveTokenFn
from ..rfc6749.signals import client_authenticated, token_revoked
from ..rfc6750.token import BearerTokenGenerator
from ..utils.consts import ACCESS_TOKEN_LENGTH, REFRESH_TOKEN_LENGTH
from ..utils.functions import (
    create_oauth_request,
    create_query_client_func,
    create_save_token_func,
    create_token_expires_in_generator,
    create_token_generator,
)
from .authenticate_client import ClientAuthentication
from .errors import InvalidScopeError, UnsupportedGrantTypeError, UnsupportedResponseTypeError
from .grants.base import BaseGrant
from .mixins import ClientMixin, TokenMixin
from .token_endpoint import TokenEndpoint
from .util import scope_to_list
from .wrappers import OAuth2Request


class AuthorizationServer:
    """Authorization server that handles Authorization Endpoint and Token
    Endpoint.

    """

    def __init__(
        self,
        config: OAuthSetting,
        oauth_client_model_cls: Type[ClientMixin],
        oauth_token_model_cls: Type[TokenMixin],
        query_client_fn: QueryClientFn = None,
        save_token_fn: SaveTokenFn = None,
    ):
        self.oauth_client_model_cls: Type[ClientMixin] = oauth_client_model_cls
        self.oauth_token_model_cls: Type[TokenMixin] = oauth_token_model_cls

        self.supported_scopes: List[str] = []
        self._token_generators: Dict[str, GroupTokenGenerator] = {}
        self._client_auth: Optional[ClientAuthentication] = None
        self._authorization_grants: List[Tuple[Type[BaseGrant], Any]] = []
        self._token_grants: List[Tuple[Type[BaseGrant], Any]] = []
        self._endpoints: Dict[str, TokenEndpoint] = {}

        self._config: OAuthSetting = config
        self._query_client: QueryClientFn = query_client_fn or create_query_client_func(self.oauth_client_model_cls)
        self._save_token: SaveTokenFn = save_token_fn or create_save_token_func(self.oauth_token_model_cls)

    def init_app(self, config: OAuthSetting, query_client: QueryClientFn = None, save_token: SaveTokenFn = None):
        """Initialize later with FastAPI app instance."""
        self._config = config
        if query_client is not None:
            self._query_client = query_client
        if save_token is not None:
            self._save_token = save_token

        self.register_token_generator('default', self.create_bearer_token_generator(self._config))
        self.supported_scopes = self._config.OAUTH2_SCOPES_SUPPORTED

    def generate_token(
        self,
        grant_type: str,
        client: ClientMixin,
        user=None,
        scope=None,
        expires_in: int = None,
        include_refresh_token: bool = True,
    ) -> Dict:
        """Generate the token dict.

        :param grant_type: current requested grant_type.
        :param client: the client that making the request.
        :param user: current authorized user.
        :param expires_in: if provided, use this value as expires_in.
        :param scope: current requested scope.
        :param include_refresh_token: should refresh_token be included.
        :return: Token dict
        """
        # generator for a specified grant type
        func: Optional[GroupTokenGenerator] = self._token_generators.get(grant_type, None)
        if not func:
            # default generator for all grant types
            func = self._token_generators.get('default', None)
        if not func:
            raise RuntimeError('No configured token generator')

        return func(grant_type, client, user, scope, expires_in, include_refresh_token)

    def register_token_generator(self, grant_type: str, func: GroupTokenGenerator):
        """Register a function as token generator for the given ``grant_type``.
        Developers MUST register a default token generator with a special
        ``grant_type=default``::

            def generate_bearer_token(grant_type, client, user=None, scope=None,
                                      expires_in=None, include_refresh_token=True):
                token = {'token_type': 'Bearer', 'access_token': ...}
                if include_refresh_token:
                    token['refresh_token'] = ...
                ...
                return token

            authorization_server.register_token_generator('default', generate_bearer_token)

        If you register a generator for a certain grant type, that generator will only work
        for the given grant type::

            authorization_server.register_token_generator('client_credentials', generate_bearer_token)

        :param grant_type: string name of the grant type
        :param func: a function to generate token
        """
        self._token_generators[grant_type] = func

    async def authenticate_client(
        self,
        request: OAuth2Request,
        methods: List[str],
        session: AsyncSession,
        endpoint='token',
    ) -> ClientMixin:
        """Authenticate client via HTTP request information with the given
        methods, such as ``client_secret_basic``, ``client_secret_post``.
        """
        if self._client_auth is None and self.query_client:
            self._client_auth = ClientAuthentication(self.query_client)
        return await self._client_auth.authenticate(
            request=request,
            methods=methods,
            session=session,
            endpoint=endpoint,
        )

    def register_client_auth_method(self, method: str, func: AuthenticateClientFn):
        """Add more client auth method. The default methods are:

        * none: The client is a public client and does not have a client secret
        * client_secret_post: The client uses the HTTP POST parameters
        * client_secret_basic: The client uses HTTP Basic

        :param method: Name of the Auth method
        :param func: Function to authenticate the client

        The auth method accept two parameters: ``query_client`` and ``request``,
        an example for this method::

            def authenticate_client_via_custom(query_client, request):
                client_id = request.headers['X-Client-Id']
                client = query_client(client_id)
                do_some_validation(client)
                return client

            authorization_server.register_client_auth_method(
                'custom', authenticate_client_via_custom)
        """
        if self._client_auth is None and self.query_client:
            self._client_auth = ClientAuthentication(self.query_client)

        self._client_auth.register(method, func)

    def validate_requested_scope(self, scope, state=None):
        """Validate if requested scope is supported by Authorization Server.
        Developers CAN re-write this method to meet your needs.
        """
        if scope and self.supported_scopes:
            scopes = set(scope_to_list(scope))
            if not set(self.supported_scopes).issuperset(scopes):
                raise InvalidScopeError(state=state)

    def register_grant(self, grant_cls: Type[BaseGrant], extensions=None):
        """Register a grant class into the endpoint registry. Developers
        can implement the grants in ``fastapi_oauth.rfc6749.grants`` and
        register with this method::

            class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
                def authenticate_user(self, credential):
                    # ...

            authorization_server.register_grant(AuthorizationCodeGrant)

        :param grant_cls: a grant class.
        :param extensions: extensions for the grant class.
        """
        if hasattr(grant_cls, 'check_authorization_endpoint'):
            self._authorization_grants.append((grant_cls, extensions))
        if hasattr(grant_cls, 'check_token_endpoint'):
            self._token_grants.append((grant_cls, extensions))

    def register_endpoint(self, endpoint_cls: Type[TokenEndpoint]):
        """Add extra endpoint to authorization server. e.g.
        RevocationEndpoint::

            authorization_server.register_endpoint(RevocationEndpoint)

        :param endpoint_cls: A endpoint class
        """
        self._endpoints[endpoint_cls.ENDPOINT_NAME] = endpoint_cls(self)

    def get_authorization_grant(self, request) -> BaseGrant:
        """Find the authorization grant for current request.

        :param request: OAuth2Request instance.
        :return: grant instance
        """
        for (grant_cls, extensions) in self._authorization_grants:
            if grant_cls.check_authorization_endpoint(request):
                return _create_grant(grant_cls, extensions, request, self)
        raise UnsupportedResponseTypeError(request.response_type)

    async def get_consent_grant(self, session: AsyncSession, request: Request, end_user=None):
        """Validate current HTTP request for authorization page. This page
        is designed for resource owner to grant or deny the authorization.
        """
        oauth_request = await self.create_oauth2_request(request)
        oauth_request.user = end_user

        grant = self.get_authorization_grant(oauth_request)
        await grant.validate_consent_request(session)
        return grant

    def get_token_grant(self, request: OAuth2Request) -> BaseGrant:
        """Find the token grant for current request.

        :param request: OAuth2Request instance.
        :return: grant instance
        """
        for (grant_cls, extensions) in self._token_grants:
            if grant_cls.check_token_endpoint(request):
                return _create_grant(grant_cls, extensions, request, self)
        raise UnsupportedGrantTypeError(request.grant_type)

    async def create_endpoint_response(self, name, request: Request, session: AsyncSession) -> Tuple[int, Any, Dict]:
        """Validate endpoint request and create endpoint response.

        :param session: Async SQLAlchemy Session
        :param name: Endpoint name
        :param request: HTTP request instance.
        :return: Response
        """
        if name not in self._endpoints:
            raise RuntimeError(f'There is no "{name}" endpoint.')

        endpoint = self._endpoints[name]
        oauth_request = await endpoint.create_endpoint_request(request)
        return await endpoint.create_endpoint_response(oauth_request, session)

    async def create_authorization_response(self, session: AsyncSession, request: Request, grant_user=None):
        """Validate authorization request and create authorization response.

        :param session: Async SQLAlchemy session
        :param request: HTTP request instance.
        :param grant_user: if granted, it is resource owner. If denied,
            it is None.
        :returns: Response
        """
        oauth_request = await self.create_oauth2_request(request)
        grant = self.get_authorization_grant(oauth_request)

        redirect_uri = await grant.validate_authorization_request(session)
        return await grant.create_authorization_response(redirect_uri, grant_user, session)

    async def create_token_response(self, session: AsyncSession, request: Request) -> Response:
        """Validate token request and create token response.

        :param session: Async SQLAlchemy session
        :param request: HTTP request instance
        """
        oauth_request = await self.create_oauth2_request(request)
        grant = self.get_token_grant(oauth_request)

        await grant.validate_token_request(session)
        return await grant.create_token_response(session)

    async def query_client(self, client_id: str, session: AsyncSession) -> Optional[ClientMixin]:
        return await self._query_client(client_id=client_id, session=session)

    async def save_token(self, token: Dict, request: OAuth2Request, session: AsyncSession):
        return await self._save_token(token, request, session)

    async def create_oauth2_request(self, request: Request) -> OAuth2Request:
        return await create_oauth_request(
            request=request,
            request_cls=OAuth2Request,
            allow_insecure_transport=self._config.OAUTH2_ALLOW_INSECURE_TRANSPORT,
        )

    def send_signal(self, name, *args, **kwargs):
        if name == 'after_authenticate_client':
            client_authenticated.send(self, *args, **kwargs)
        elif name == 'after_revoke_token':
            token_revoked.send(self, *args, **kwargs)

    @classmethod
    def create_bearer_token_generator(cls, config: OAuthSetting) -> BearerTokenGenerator:
        """Create a generator function for generating ``token`` value. This
        method will create a Bearer Token generator with
        :class:`fastapi_oauth.rfc6750.BearerToken`.

        Configurable settings:

        1. OAUTH2_ACCESS_TOKEN_GENERATOR: Boolean or import string, default is True.
        2. OAUTH2_REFRESH_TOKEN_GENERATOR: Boolean or import string, default is False.
        3. OAUTH2_TOKEN_EXPIRES_IN: Dict or import string, default is None.

        By default, it will not generate ``refresh_token``, which can be turned on by
        configure ``OAUTH2_REFRESH_TOKEN_GENERATOR``.

        Here are some examples of the token generator::

            OAUTH2_ACCESS_TOKEN_GENERATOR = 'your_project.generators.gen_token'

            # and in module `your_project.generators`, you can define:

            def gen_token(client, grant_type, user, scope):
                # generate token according to these parameters
                token = create_random_token()
                return f'{client.id}-{user.id}-{token}'

        Here is an example of ``OAUTH2_TOKEN_EXPIRES_IN``::

            OAUTH2_TOKEN_EXPIRES_IN = {
                'authorization_code': 864000,
                'urn:ietf:params:oauth:grant-type:jwt-bearer': 3600,
            }
        """
        conf = config.OAUTH2_ACCESS_TOKEN_GENERATOR
        access_token_generator = create_token_generator(conf, ACCESS_TOKEN_LENGTH)
        if access_token_generator is None:
            raise OAuth2Error("Can't create access token generator!")

        conf = config.OAUTH2_REFRESH_TOKEN_GENERATOR
        refresh_token_generator = create_token_generator(conf, REFRESH_TOKEN_LENGTH, allow_none=False)

        expires_conf = config.OAUTH2_TOKEN_EXPIRES_IN
        expires_generator = create_token_expires_in_generator(expires_conf)
        return BearerTokenGenerator(
            access_token_generator=access_token_generator,
            refresh_token_generator=refresh_token_generator,
            expires_generator=expires_generator,
        )


def _create_grant(
    grant_cls: Type[BaseGrant],
    extensions,
    request,
    server: AuthorizationServer,
):
    grant = grant_cls(request, server)
    if extensions:
        for ext in extensions:
            ext(grant)
    return grant
