from typing import TYPE_CHECKING, ClassVar, Protocol

from dmr.exceptions import NotAuthenticatedError
from dmr.security.blocklist.models import BlacklistedJWTToken
from dmr.security.jwt.token import JWTToken

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser


class _JWTAuth(Protocol):
    blocklist_model: ClassVar[type[BlacklistedJWTToken]] = BlacklistedJWTToken


class _JWTSyncAuth(_JWTAuth, Protocol):
    def check_auth(
        self,
        user: 'AbstractBaseUser',
        token: JWTToken,
    ) -> None: ...

    def get_user(self, token: JWTToken) -> 'AbstractBaseUser': ...


class _JWTAsyncAuth(_JWTAuth, Protocol):
    async def check_auth(
        self,
        user: 'AbstractBaseUser',
        token: JWTToken,
    ) -> None: ...

    async def get_user(self, token: JWTToken) -> 'AbstractBaseUser': ...


class JWTTokenBlacklistSyncMixin:
    """Sync mixin for working with tokens blacklist."""

    def check_auth(
        self: _JWTSyncAuth,
        user: 'AbstractBaseUser',
        token: JWTToken,
    ) -> None:
        """Check if the token is in the black list, if so raise the error."""
        super().check_auth(user, token)  # type: ignore[safe-super]
        if BlacklistedJWTToken.objects.filter(jti=token.jti).exists():
            raise NotAuthenticatedError

    def blacklist(
        self: _JWTSyncAuth,
        token: JWTToken,
    ) -> tuple[BlacklistedJWTToken, bool]:
        """Add token to the blacklist."""
        jti = token.jti
        exp = token.exp
        user = self.get_user(token)

        return self.blocklist_model.objects.get_or_create(
            user=user,
            jti=jti,
            expires_at=exp,
        )


class JWTTokenBlacklistAsyncMixin:
    """Async mixin for working with tokens blacklist."""

    async def check_auth(
        self: _JWTAsyncAuth,
        user: 'AbstractBaseUser',
        token: JWTToken,
    ) -> None:
        """Check if the token is in the black list, if so raise the error."""
        await super().check_auth(user, token)  # type: ignore[safe-super]
        if BlacklistedJWTToken.objects.filter(jti=token.jti).exists():
            raise NotAuthenticatedError

    async def blacklist(
        self: _JWTAsyncAuth,
        token: JWTToken,
    ) -> tuple[BlacklistedJWTToken, bool]:
        """Add token to the blacklist."""
        jti = token.jti
        exp = token.exp
        user = await self.get_user(token)

        return self.blocklist_model.objects.get_or_create(
            user=user,
            jti=jti,
            expires_at=exp,
        )