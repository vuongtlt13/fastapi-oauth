import time
from typing import TYPE_CHECKING, Dict, Optional

from starlette.requests import Request

from .errors import InsecureTransportError

if TYPE_CHECKING:
    from ..sqla_oauth2.client_mixin import ClientMixin


class OAuth2Token(dict):
    def __init__(self, params):
        if params.get('expires_at'):
            params['expires_at'] = int(params['expires_at'])
        elif params.get('expires_in'):
            params['expires_at'] = int(time.time()) + \
                                   int(params['expires_in'])
        super(OAuth2Token, self).__init__(params)

    def is_expired(self):
        expires_at = self.get('expires_at')
        if not expires_at:
            return None
        return expires_at < time.time()

    @classmethod
    def from_dict(cls, token):
        if isinstance(token, dict) and not isinstance(token, cls):
            token = cls(token)
        return token


class OAuth2Request(object):
    def __init__(self, request: Request):
        self._raw_request: Request = request
        InsecureTransportError.check(str(request.url))

        self.data: Dict = {}
        self.json: Dict = {}
        self.form: Dict = {}

        #: authenticate method
        self.auth_method = None
        #: authenticated user on this request
        self.user = None
        #: authorization_code or token model instance
        self.credential = None
        #: client which sending this request
        self.client: Optional['ClientMixin'] = None

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
    def client_id(self) -> str:
        """The authorization server issues the registered client a client
        identifier -- a unique string representing the registration
        information provided by the client. The value is extracted from
        request.

        :return: string
        """
        return self.data.get('client_id')

    @property
    def response_type(self) -> str:
        rt = self.data.get('response_type')
        if rt and ' ' in rt:
            # sort multiple response types
            return ' '.join(sorted(rt.split()))
        return rt

    @property
    def grant_type(self) -> str:
        return self.data.get('grant_type')

    @property
    def redirect_uri(self) -> str:
        return self.data.get('redirect_uri')

    @property
    def scope(self) -> str:
        return self.data.get('scope')

    @property
    def state(self) -> str:
        return self.data.get('state')

    @property
    def token_type_hint(self) -> str:
        return self.data.get('token_type_hint')
