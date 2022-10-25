import time
from typing import TYPE_CHECKING, Any, Dict, Optional, Union

from starlette.requests import Request

from .errors import InsecureTransportError
from .mixins import AuthorizationCodeMixin, ClientMixin, TokenMixin, UserMixin

if TYPE_CHECKING:
    from ..common.types import OAuth2RequestDataPayloadDict


class OAuth2Token(dict):
    def __init__(self, params: Dict):
        if params.get('expires_at', None):
            params['expires_at'] = int(params['expires_at'])
        elif params.get('expires_in', None):
            params['expires_at'] = int(time.time()) + int(params['expires_in'])
        super().__init__(params)

    def is_expired(self):
        expires_at = self.get('expires_at')
        if not expires_at:
            return None
        return expires_at < time.time()

    @classmethod
    def from_dict(cls, token: Union[Dict, 'OAuth2Token']):
        if isinstance(token, dict) and not isinstance(token, cls):
            token = cls(token)
        return token


class OAuth2Request(object):
    def __init__(self, request: Request, allow_insecure_transport=False):
        self._raw_request: Request = request
        self._validate_transport(str(request.url), allow_insecure_transport)

        self.data: OAuth2RequestDataPayloadDict = {}
        self.json: Dict[str, Optional[Any]] = {}
        self.form: Dict[str, Optional[Any]] = {}

        #: authenticate method
        self.auth_method: Optional[str] = None
        #: authenticated user on this request
        self.user: Optional[UserMixin] = None
        #: authorization_code or token model instance
        self.credential: Union[Optional[AuthorizationCodeMixin], Optional[TokenMixin]] = None
        #: client which sending this request
        self.client: Optional[ClientMixin] = None

    async def prepare_data(self):
        try:
            json_data = await self._raw_request.json()
        except:
            json_data = {}

        self.json = json_data

        try:
            form_data = await self._raw_request.form()
        except:
            form_data = {}

        self.form = form_data

        self.data = {
            **self._raw_request.query_params,
            **form_data,
            **json_data,
        }

    @property
    def raw_request(self) -> Request:
        return self._raw_request

    @property
    def client_id(self) -> Optional[str]:
        """The authorization server issues the registered client a client
        identifier -- a unique string representing the registration
        information provided by the client. The value is extracted from
        request.

        :return: string
        """
        return self.data.get('client_id', None)

    @property
    def response_type(self) -> Optional[str]:
        rt = self.data.get('response_type', None)
        if rt and ' ' in rt:
            # sort multiple response types
            return ' '.join(sorted(rt.split()))
        return rt

    @property
    def grant_type(self) -> Optional[str]:
        return self.data.get('grant_type', None)

    @property
    def redirect_uri(self) -> Optional[str]:
        return self.data.get('redirect_uri', None)

    @property
    def scope(self) -> Optional[str]:
        return self.data.get('scope', None)

    @property
    def state(self) -> Optional[str]:
        return self.data.get('state', None)

    @property
    def token_type_hint(self) -> Optional[str]:
        return self.data.get('token_type_hint', None)

    @classmethod
    def _validate_transport(cls, uri: str, allow_insecure_transport=False):
        """Check and raise InsecureTransportError with the given URI."""
        if allow_insecure_transport:
            return True

        uri = uri.lower()
        if uri.startswith(('https://', 'http://localhost:', 'http://127.0.0.1:')):
            raise InsecureTransportError()
