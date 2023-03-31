from datetime import datetime, timezone, timedelta
import pytest, mongomock, jwt
from unittest.mock import patch

import auth_server

@pytest.fixture()
def app():
    with patch.object(auth_server, 'db_open', return_value=mongomock.MongoClient()):
        yield auth_server.create_app()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def public_key():
    with open('jwtRS256.key.pub') as f:
        return f.read()
    
    
@pytest.fixture()
def private_key():
    with open('jwtRS256.key') as f:
        return f.read()
    

def generate_access_token_expiry():
    dt = datetime.now(tz=timezone.utc)
    td = timedelta(minutes=auth_server.ACCESS_TOKEN_EXPIRY_MINUTES)

    return int((dt + td).timestamp())


def generate_refresh_token_expiry():
    dt = datetime.now(tz=timezone.utc)
    td = timedelta(minutes=auth_server.REFRESH_TOKEN_EXPIRY_MINUTES)

    return int((dt + td).timestamp())


def generate_token_expiry_in_past():
    dt = datetime.now(tz=timezone.utc)
    td = timedelta(minutes=-1)
    return int((dt + td).timestamp())


def generate_token(private_key, user_id, scope, expiry):
    return jwt.encode(
        {"exp": expiry, "user_id": user_id, "scope": scope},
        private_key,
        algorithm="RS256"
    )