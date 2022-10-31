from sqlalchemy.ext.asyncio import AsyncSession

from ..consts import DEFAULT_JSON_HEADERS
from ..rfc6749 import InvalidRequestError, TokenEndpoint, UnsupportedTokenTypeError


class RevocationEndpoint(TokenEndpoint):
    """Implementation of revocation endpoint which is described in
    `RFC7009`_.

    .. _RFC7009: https://tools.ietf.org/html/rfc7009
    """
    #: Endpoint name to be registered
    ENDPOINT_NAME = 'revocation'

    async def authenticate_token(self, request, client, session: AsyncSession):
        """The client constructs the request by including the following
        parameters using the "application/x-www-form-urlencoded" format in
        the HTTP request entity-body:

        token
            REQUIRED.  The token that the client wants to get revoked.

        token_type_hint
            OPTIONAL.  A hint about the type of the token submitted for
            revocation.
        """
        if 'token' not in request.form:
            raise InvalidRequestError()

        hint = request.form.get('token_type_hint')
        if hint and hint not in self.SUPPORTED_TOKEN_TYPES:
            raise UnsupportedTokenTypeError()

        token = await self.query_token(request.form['token'], hint, session)
        if token and token.check_client(client):
            return token

    async def create_endpoint_response(self, request, session: AsyncSession):
        """Validate revocation request and create the response for revocation.
        For example, a client may request the revocation of a refresh token
        with the following request::

            POST /revoke HTTP/1.1
            Host: server.example.com
            Content-Type: application/x-www-form-urlencoded
            Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

            token=45ghiukldjahdnhzdauz&token_type_hint=refresh_token

        :returns: (status_code, body, headers)
        """
        # The authorization server first validates the client credentials
        client = self.authenticate_endpoint_client(request)

        # then verifies whether the token was issued to the client making
        # the revocation request
        token = await self.authenticate_token(request, client, session)

        # the authorization server invalidates the token
        if token:
            await self.revoke_token(token, request, session)
            self.server.send_signal(
                'after_revoke_token',
                token=token,
                client=client,
            )
        return 200, {}, DEFAULT_JSON_HEADERS

    async def query_token(self, token_string, token_type_hint, session: AsyncSession):
        """Get the token from database/storage by the given token string.
        Developers should implement this method::

            def query_token(self, token_string, token_type_hint):
                if token_type_hint == 'access_token':
                    return Token.query_by_access_token(token_string)
                if token_type_hint == 'refresh_token':
                    return Token.query_by_refresh_token(token_string)
                return Token.query_by_access_token(token_string) or \
                    Token.query_by_refresh_token(token_string)
        """
        raise NotImplementedError()

    async def revoke_token(self, token, request, session: AsyncSession):
        """Mark token as revoked. Since token MUST be unique, it would be
        dangerous to delete it. Consider this situation:

        1. Jane obtained a token XYZ
        2. Jane revoked (deleted) token XYZ
        3. Bob generated a new token XYZ
        4. Jane can use XYZ to access Bob's resource

        It would be secure to mark a token as revoked::

            def revoke_token(self, token, request):
                hint = request.form.get('token_type_hint')
                if hint == 'access_token':
                    token.access_token_revoked = True
                else:
                    token.access_token_revoked = True
                    token.refresh_token_revoked = True
                token.save()
        """
        raise NotImplementedError()
