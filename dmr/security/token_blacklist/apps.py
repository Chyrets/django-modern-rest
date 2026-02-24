from django.apps import AppConfig


class TokenBlacklistConfig(AppConfig):
    """AppConfig for token_blacklist app."""

    name = 'dmr.security.token_blacklist'
    verbose_name = 'Token Blacklist'
    default_auto_field = 'django.db.models.BigAutoField'
