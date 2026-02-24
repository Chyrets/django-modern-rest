from typing import TYPE_CHECKING, override

from dmr.exceptions import NotAuthenticatedError
from dmr.security.jwt.token import JWTToken
from dmr.security.token_blacklist.models import BlacklistedJWTToken

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser

    from dmr.security.jwt.auth import JWTAsyncAuth, JWTSyncAuth

    _BaseSync = JWTSyncAuth
    _BaseAsync = JWTAsyncAuth
else:
    _BaseSync = object
    _BaseAsync = object


class JWTTokenBlacklistSyncMixin(_BaseSync):
    """Sync mixin for working with tokens blacklist."""

    @override
    def check_auth(self, user: 'AbstractBaseUser', token: JWTToken) -> None:
        """Check if the token is in the black list, if so raise the error."""
        super().check_auth(user, token)
        if BlacklistedJWTToken.objects.filter(jti=token.jti).exists():
            raise NotAuthenticatedError

    def blacklist(self, token: JWTToken) -> tuple[BlacklistedJWTToken, bool]:
        """Add token to the blacklist."""
        jti = token.jti
        exp = token.exp
        user = self.get_user(token)

        return BlacklistedJWTToken.objects.get_or_create(
            user=user,
            jti=jti,
            expires_at=exp,
        )


class JWTTokenBlacklistAsyncMixin(_BaseAsync):
    """Async mixin for working with tokens blacklist."""

    @override
    async def check_auth(
        self,
        user: 'AbstractBaseUser',
        token: JWTToken,
    ) -> None:
        """Check if the token is in the black list, if so raise the error."""
        await super().check_auth(user, token)
        if BlacklistedJWTToken.objects.filter(jti=token.jti).exists():
            raise NotAuthenticatedError

    async def blacklist(
        self,
        token: JWTToken,
    ) -> tuple[BlacklistedJWTToken, bool]:
        """Add token to the blacklist."""
        jti = token.jti
        exp = token.exp
        user = await self.get_user(token)

        return BlacklistedJWTToken.objects.get_or_create(
            user=user,
            jti=jti,
            expires_at=exp,
        )
