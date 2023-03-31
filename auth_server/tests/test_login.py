import jwt

from conftest import generate_access_token_expiry, generate_refresh_token_expiry

# Test signing up a new user and logging in as them
def test_signup_and_login(client, public_key):
    # Genrate token expiry times
    access_token_expiry = generate_access_token_expiry()
    refresh_token_expiry = generate_refresh_token_expiry()

    # Sign up the user
    response = client.post("/auth/signup", json={"email": "test@test.com", "password": "test"})
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
    assert access_token_expiry <= decoded_login_access["exp"] <= generate_access_token_expiry()
    assert refresh_token_expiry <= decoded_login_refresh["exp"] <= generate_refresh_token_expiry()

