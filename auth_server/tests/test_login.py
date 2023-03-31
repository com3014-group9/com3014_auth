import jwt

from conftest import generate_access_token_expiry, generate_refresh_token_expiry

# Test signing up a new user and logging in as them
def test_signup_and_login(client, public_key):
    # Generate token expiry times
    access_token_expiry = generate_access_token_expiry()
    refresh_token_expiry = generate_refresh_token_expiry()

    # Sign up the user
    response = client.post("/auth/signup", json={"email": "test@test.com", "password": "test"})
    assert response.status_code == 200
    signup_access = response.json["access_token"]
    signup_refresh = response.json["refresh_token"]

    decoded_signup_access = jwt.decode(signup_access, public_key, algorithms=["RS256"])
    signup_access_user_id = str(decoded_signup_access["user_id"])
    signup_access_scope = str(decoded_signup_access["scope"])

    decoded_signup_refresh = jwt.decode(signup_refresh, public_key, algorithms=["RS256"])
    signup_refresh_user_id = str(decoded_signup_refresh["user_id"])
    signup_refresh_scope = str(decoded_signup_refresh["scope"])

    # Log the user in and test that the tokens we get contain the same data
    response = client.post("/auth/login", json={"email": "test@test.com", "password": "test"})
    assert response.status_code == 200
    login_access = response.json["access_token"]
    login_refresh = response.json["refresh_token"]

    decoded_login_access = jwt.decode(login_access, public_key, algorithms=["RS256"])
    login_access_user_id = str(decoded_login_access["user_id"])
    login_access_scope = str(decoded_login_access["scope"])

    decoded_login_refresh = jwt.decode(login_refresh, public_key, algorithms=["RS256"])
    login_refresh_user_id = str(decoded_login_refresh["user_id"])
    login_refresh_scope = str(decoded_login_refresh["scope"])

    assert len(login_access_user_id) == 24
    assert login_access_scope == "access"

    assert len(login_refresh_user_id) == 24
    assert login_refresh_scope == "refresh"

    assert login_access_user_id == signup_access_user_id
    assert login_refresh_user_id == signup_refresh_user_id

    assert login_access_scope == signup_access_scope
    assert login_refresh_scope == signup_refresh_scope

    # Check expiry times of tokens provided by login
    # We can't know the exact time it should be, but if it is between times generated before and after
    # the request, that should be close enough
    assert access_token_expiry <= decoded_login_access["exp"] <= generate_access_token_expiry()
    assert refresh_token_expiry <= decoded_login_refresh["exp"] <= generate_refresh_token_expiry()


# Test failure if no json body
def test_login_no_json(client):
    response = client.post("/auth/login")
    assert response.status_code == 400


# Test failure if user does not exist
def test_login_user_does_not_exist(client):
    response = client.post("/auth/login", json={"email": "test@test.com", "password": "test"})
    assert response.status_code == 401


# Test failure if password is incorrect
def test_login_password_incorrect(client):
    response = client.post("/auth/signup", json={"email": "test@test.com", "password": "test"})
    assert response.status_code == 200

    response = client.post("/auth/login", json={"email": "test@test.com", "password": "incorrect"})
    assert response.status_code == 401