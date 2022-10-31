from src.fastapi_oauth.common.encoding import json_loads


def test_json_loads():
    actual = json_loads('{"a": 1, "b": "2"}')
    expect = {'a': 1, 'b': '2'}
    assert expect == actual
