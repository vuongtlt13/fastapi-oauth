name = 'FastAPI-OAuth'
version = '0.1.0'
author = 'Do Quoc Vuong <vuongtlt13@gmail.com>'
homepage = 'https://github.com/vuongtlt13/fastapi-oauth'
DEFAULT_USER_AGENT = '{}/{} (+{})'.format(name, version, homepage)

DEFAULT_JSON_HEADERS = [
    ('Content-Type', 'application/json'),
    ('Cache-Control', 'no-store'),
    ('Pragma', 'no-cache'),
]

ACCESS_TOKEN_LENGTH = 42
REFRESH_TOKEN_LENGTH = 48
