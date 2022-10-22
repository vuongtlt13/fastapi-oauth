from typing import Dict, List, Optional, Union

from pydantic import BaseSettings


class OAuthSetting(BaseSettings):
    OAUTH2_SCOPES_SUPPORTED: List[str] = ['vuong-open-id']
    OAUTH2_ERROR_URIS: List[str] = ['oauth/error']

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
