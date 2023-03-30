import pytest, mongomock
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