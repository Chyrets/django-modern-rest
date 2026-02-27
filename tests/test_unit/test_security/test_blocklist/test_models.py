import datetime as dt
import secrets

import pytest
from django.contrib.auth.models import User
from faker import Faker

from dmr.security.blocklist.models import BlacklistedJWTToken

jti = secrets.token_hex()
expires_at = dt.datetime.now(dt.UTC) + dt.timedelta(days=1)


@pytest.fixture
def user(faker: Faker) -> User:
    """Create fake user for tests."""
    return User.objects.create_user(
        faker.unique.user_name(),
        faker.unique.email(),
        faker.password(),
    )


@pytest.fixture
def token(user: User) -> BlacklistedJWTToken:
    """Create blacklisted token for tests."""
    return BlacklistedJWTToken.objects.create(
        user=user,
        jti=jti,
        expires_at=expires_at,
    )


@pytest.mark.django_db
def test_token_user_field(token: BlacklistedJWTToken, user: User) -> None:
    """Test user field."""
    assert token.user == user


@pytest.mark.django_db
def test_token_jti_field(token: BlacklistedJWTToken) -> None:
    """Test jti field."""
    assert token.jti == jti


@pytest.mark.django_db
def test_token_expires_at_field(token: BlacklistedJWTToken) -> None:
    """Test expires_at field."""
    assert token.expires_at == expires_at


@pytest.mark.django_db
def test_token_str(token: BlacklistedJWTToken) -> None:
    """Test token str."""
    assert str(token) == f'Token for {token.user} {token.jti}'
