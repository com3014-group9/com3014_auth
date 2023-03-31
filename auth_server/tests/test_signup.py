import jwt

from conftest import generate_access_token_expiry, generate_refresh_token_expiry

# Test signing up a new user
def test_signup(client, public_key):
    # Genrate token expiry times
    access_token_expiry = generate_access_token_expiry()
    refresh_token_expiry = generate_refresh_token_expiry()

    # Test the reponse format
    response = client.post("/auth/signup", json={"email": "test@test.com", "password": "test"})
    assert response.status_code == 200
    assert response.json["access_token"] != None
    assert response.json["refresh_token"] != None

    # Test we can decode the access token
    decoded_access = jwt.decode(response.json["access_token"], public_key, algorithms=["RS256"])
    access_user_id = str(decoded_access["user_id"])
    access_scope = str(decoded_access["scope"])
    assert len(access_user_id) == 24
    assert access_scope == "access"

    # Test that expiry is between expiry generated before request and after request 
    assert access_token_expiry <= decoded_access["exp"] <= generate_access_token_expiry()

    # Test we can decode the refresh token
    decoded_refresh = jwt.decode(response.json["refresh_token"], public_key, algorithms=["RS256"])
    refresh_user_id = str(decoded_refresh["user_id"])
    refresh_scope = str(decoded_refresh["scope"])
    assert len(refresh_user_id) == 24
    assert refresh_scope == "refresh"

    # Test that expiry is between expiry generated before request and after request 
    assert refresh_token_expiry <= decoded_refresh["exp"] <= generate_refresh_token_expiry()

# Test that signup fails if email is already in use
def test_signup_duplicate_email(client):
    client.post("/auth/signup", json={"email": "test@test.com", "password": "test"})
    response = client.post("/auth/signup", json={"email": "test@test.com", "password": "test"})
    assert response.status_code == 409

# Test failure if no json body
def test_signup_no_json(client):
    response = client.post("/auth/signup")
    assert response.status_code == 400

# Test failure if email is blank
def test_signup_blank_email(client):
    response = client.post("/auth/signup", json={"email": "", "password": "test"})
    assert response.status_code == 400

# Test failure if password is blank
def test_signup_blank_password(client):
    response = client.post("/auth/signup", json={"email": "test@test.com", "password": ""})
    assert response.status_code == 400