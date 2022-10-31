from typing import Any, Dict, List, Optional, Tuple, Union

from pydantic import BaseSettings, validator

DEFAULT_SCOPE = 'openid'


class OAuthSetting(BaseSettings):
    OAUTH2_USE_DEFAULT_SCOPE: bool = True

    OAUTH2_SCOPES_SUPPORTED: List[str] = []

    @validator('OAUTH2_SCOPES_SUPPORTED')
    def unique_and_add_default_scope(cls, value, values, config, field):
        if value is None:
            value = []

        if values['OAUTH2_USE_DEFAULT_SCOPE']:
            value.append(DEFAULT_SCOPE)

        value = list(set(value))
        return value

    """
    OAUTH2_ACCESS_TOKEN_GENERATOR: Boolean or import string, default is True.

    Here are some examples of the token generator::

        OAUTH2_ACCESS_TOKEN_GENERATOR = 'your_project.generators.gen_token'

        # and in module `your_project.generators`, you can define:

        def gen_token(client, grant_type, user, scope):
            # generate token according to these parameters
            token = create_random_token()
            return f'{client.id}-{user.id}-{token}'
    """
    OAUTH2_ACCESS_TOKEN_GENERATOR: Union[bool, str] = True

    """
    OAUTH2_REFRESH_TOKEN_GENERATOR: Boolean or import string, default is False.
    By default, it will not generate ``refresh_token``, which can be turned on by
        configure ``OAUTH2_REFRESH_TOKEN_GENERATOR``.
    """
    OAUTH2_REFRESH_TOKEN_GENERATOR: Union[bool, str] = False

    """
    OAUTH2_TOKEN_EXPIRES_IN: Dict or import string, default is None.
    Here is an example of ``OAUTH2_TOKEN_EXPIRES_IN``::

        OAUTH2_TOKEN_EXPIRES_IN = {
            'authorization_code': 864000,
            'urn:ietf:params:oauth:grant-type:jwt-bearer': 3600,
        }
    """
    OAUTH2_TOKEN_EXPIRES_IN: Optional[Union[Dict, str]] = None

    OAUTH2_ALLOW_INSECURE_TRANSPORT: bool = False

    class Config(BaseSettings.Config):
        @classmethod
        def parse_env_var(cls, field_name: str, raw_val: str) -> Any:
            if field_name == 'OAUTH2_SCOPES_SUPPORTED':
                return raw_val.split(',')
            return cls.json_loads(raw_val)
