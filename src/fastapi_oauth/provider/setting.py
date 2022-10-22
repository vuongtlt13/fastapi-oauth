from pydantic import BaseSettings

class OAuthSetting(BaseSettings):
    OAUTH2_SCOPES_SUPPORTED: List[str]
    OAUTH2_ERROR_URIS: List[str]