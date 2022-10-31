import base64
import json
from typing import Optional


def to_bytes(x, charset='utf-8', errors='strict') -> Optional[bytes]:
    if x is None:
        return None
    if isinstance(x, bytes):
        return x
    if isinstance(x, str):
        return x.encode(charset, errors)
    if isinstance(x, (int, float)):
        return str(x).encode(charset, errors)
    return bytes(x)


def to_unicode(x, charset='utf-8', errors='strict') -> Optional[str]:
    if x is None or isinstance(x, str):
        return x
    if isinstance(x, bytes):
        return x.decode(charset, errors)
    return str(x)


def to_native(x, encoding='ascii') -> str:
    if isinstance(x, str):
        return x
    return x.decode(encoding)


def json_loads(s):
    return json.loads(s)


def json_dumps(data, ensure_ascii=False):
    return json.dumps(data, ensure_ascii=ensure_ascii, separators=(',', ':'))


def urlsafe_b64decode(s):
    s += b'=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def urlsafe_b64encode(s):
    return base64.urlsafe_b64encode(s).rstrip(b'=')
