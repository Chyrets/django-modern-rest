from typing import override

from django.conf import settings
from django.db import models


class BlacklistedJWTToken(models.Model):
    """Model for Blacklisted token."""

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    jti = models.CharField(unique=True, max_length=255)
    expires_at = models.DateTimeField()
    blacklisted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Blacklisted Token'
        verbose_name_plural = 'Blacklisted Tokens'
        abstract = 'dmr.security.token_blacklist' not in settings.INSTALLED_APPS
        ordering = ('user',)

    @override
    def __str__(self) -> str:
        return f'Token for {self.user} {self.jti}'
