from ..common.encoding import to_unicode
from ..common.urls import add_params_to_uri
from .errors import MismatchingStateException, MissingCodeException, MissingTokenException, MissingTokenTypeException
from .util import list_to_scope


def prepare_grant_uri(
    uri: str,
    client_id: str,
    response_type: str,
    redirect_uri: str=None,
    scope: str=None,
    state=None,
    **kwargs
):
    """Prepare the authorization grant request URI.

    The client constructs the request URI by adding the following
    parameters to the query component of the authorization endpoint URI
    using the ``application/x-www-form-urlencoded`` format:

    :param uri: The authorize endpoint to fetch "code" or "token".
    :param client_id: The client identifier as described in `Section 2.2`_.
    :param response_type: To indicate which OAuth 2 grant/flow is required,
                          "code" and "token".
    :param redirect_uri: The client provided URI to redirect back to after
                         authorization as described in `Section 3.1.2`_.
    :param scope: The scope of the access request as described by
                  `Section 3.3`_.
    :param state: An opaque value used by the client to maintain
                  state between the request and callback.  The authorization
                  server includes this value when redirecting the user-agent
                  back to the client.  The parameter SHOULD be used for
                  preventing cross-site request forgery as described in
                  `Section 10.12`_.
    :param kwargs: Extra arguments to embed in the grant/authorization URL.

    An example of an authorization code grant authorization URL::

        /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
        &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb

    .. _`Section 2.2`: https://tools.ietf.org/html/rfc6749#section-2.2
    .. _`Section 3.1.2`: https://tools.ietf.org/html/rfc6749#section-3.1.2
    .. _`Section 3.3`: https://tools.ietf.org/html/rfc6749#section-3.3
    .. _`section 10.12`: https://tools.ietf.org/html/rfc6749#section-10.12
    """
    params = [
        ('response_type', response_type),
        ('client_id', client_id),
    ]

    if redirect_uri:
        params.append(('redirect_uri', redirect_uri))
    if scope:
        params.append(('scope', list_to_scope(scope)))
    if state:
        params.append(('state', state))

    for k in kwargs:
        if kwargs[k]:
            params.append((to_unicode(k), kwargs[k]))

    return add_params_to_uri(uri, params)


def prepare_token_request(grant_type, body='', redirect_uri=None, **kwargs):
    """Prepare the access token request. Per `Section 4.1.3`_.

    The client makes a request to the token endpoint by adding the
    following parameters using the ``application/x-www-form-urlencoded``
    format in the HTTP request entity-body:

    :param grant_type: To indicate grant type being used, i.e. "password",
            "authorization_code" or "client_credentials".
    :param body: Existing request body to embed parameters in.
    :param redirect_uri: If the "redirect_uri" parameter was included in the
                         authorization request as described in
                         `Section 4.1.1`_, and their values MUST be identical.
    :param kwargs: Extra arguments to embed in the request body.

    An example of an authorization code token request body::

        grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
        &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb

    .. _`Section 4.1.1`: https://tools.ietf.org/html/rfc6749#section-4.1.1
    .. _`Section 4.1.3`: https://tools.ietf.org/html/rfc6749#section-4.1.3
    """
    params = [('grant_type', grant_type)]

    if redirect_uri:
        params.append(('redirect_uri', redirect_uri))

    if 'scope' in kwargs:
        kwargs['scope'] = list_to_scope(kwargs['scope'])

    if grant_type == 'authorization_code' and 'code' not in kwargs:
        raise MissingCodeException()

    for k in kwargs:
        if kwargs[k]:
            params.append((to_unicode(k), kwargs[k]))

    return add_params_to_qs(body, params)


def parse_authorization_code_response(uri, state=None):
    """Parse authorization grant response URI into a dict.

    If the resource owner grants the access request, the authorization
    server issues an authorization code and delivers it to the client by
    adding the following parameters to the query component of the
    redirection URI using the ``application/x-www-form-urlencoded`` format:

    **code**
            REQUIRED.  The authorization code generated by the
            authorization server.  The authorization code MUST expire
            shortly after it is issued to mitigate the risk of leaks.  A
            maximum authorization code lifetime of 10 minutes is
            RECOMMENDED.  The client MUST NOT use the authorization code
            more than once.  If an authorization code is used more than
            once, the authorization server MUST deny the request and SHOULD
            revoke (when possible) all tokens previously issued based on
            that authorization code.  The authorization code is bound to
            the client identifier and redirection URI.

    **state**
            REQUIRED if the "state" parameter was present in the client
            authorization request.  The exact value received from the
            client.

    :param uri: The full redirect URL back to the client.
    :param state: The state parameter from the authorization request.

    For example, the authorization server redirects the user-agent by
    sending the following HTTP response:

    .. code-block:: http

        HTTP/1.1 302 Found
        Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA
                &state=xyz

    """
    query = urlparse.urlparse(uri).query
    params = dict(urlparse.parse_qsl(query))

    if 'code' not in params:
        raise MissingCodeException()

    params_state = params.get('state')
    if state and params_state != state:
        raise MismatchingStateException()

    return params


def parse_implicit_response(uri, state=None):
    """Parse the implicit token response URI into a dict.

    If the resource owner grants the access request, the authorization
    server issues an access token and delivers it to the client by adding
    the following parameters to the fragment component of the redirection
    URI using the ``application/x-www-form-urlencoded`` format:

    **access_token**
            REQUIRED.  The access token issued by the authorization server.

    **token_type**
            REQUIRED.  The type of the token issued as described in
            Section 7.1.  Value is case insensitive.

    **expires_in**
            RECOMMENDED.  The lifetime in seconds of the access token.  For
            example, the value "3600" denotes that the access token will
            expire in one hour from the time the response was generated.
            If omitted, the authorization server SHOULD provide the
            expiration time via other means or document the default value.

    **scope**
            OPTIONAL, if identical to the scope requested by the client,
            otherwise REQUIRED.  The scope of the access token as described
            by Section 3.3.

    **state**
            REQUIRED if the "state" parameter was present in the client
            authorization request.  The exact value received from the
            client.

    Similar to the authorization code response, but with a full token provided
    in the URL fragment:

    .. code-block:: http

        HTTP/1.1 302 Found
        Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
                &state=xyz&token_type=example&expires_in=3600
    """
    fragment = urlparse.urlparse(uri).fragment
    params = dict(urlparse.parse_qsl(fragment, keep_blank_values=True))

    if 'access_token' not in params:
        raise MissingTokenException()

    if 'token_type' not in params:
        raise MissingTokenTypeException()

    if state and params.get('state', None) != state:
        raise MismatchingStateException()

    return params
