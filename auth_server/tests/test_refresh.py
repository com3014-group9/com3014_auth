import jwt, time
from datetime import datetime, timezone, timedelta

from conftest import generate_access_token_expiry, generate_refresh_token_expiry, generate_token_expiry_in_past, generate_token

# Test requesting a new access token
def test_refresh_access_token(client, public_key):
    # Generate token expiry times
    access_token_expiry = generate_access_token_expiry()
    refresh_token_expiry = generate_refresh_token_expiry()

    # Sign up the user
    response = client.post("/auth/signup", json={"email": "test@test.com", "password": "test"})
    assert response.status_code == 200
    signup_access = response.json["access_token"]
    signup_refresh = response.json["refresh_token"]

    # Wait 1 second so the tokens are different
    time.sleep(1)

    # Refresh the access token
    response = client.post("/auth/refresh", headers={"Authorization": f"Bearer {signup_refresh}"})
    assert response.status_code == 200
    refresh_access = response.json["access_token"]
    refresh_refresh = response.json["refresh_token"]

    # Check that the tokens are different
    assert signup_access != refresh_access
    assert signup_refresh != refresh_refresh

    # Check that the tokens contain the same data
    decoded_signup_access = jwt.decode(signup_access, public_key, algorithms=["RS256"])
    signup_access_user_id = str(decoded_signup_access["user_id"])
    signup_access_scope = str(decoded_signup_access["scope"])

    decoded_signup_refresh = jwt.decode(signup_refresh, public_key, algorithms=["RS256"])
    signup_refresh_user_id = str(decoded_signup_refresh["user_id"])
    signup_refresh_scope = str(decoded_signup_refresh["scope"])

    decoded_refresh_access = jwt.decode(refresh_access, public_key, algorithms=["RS256"])
    refresh_access_user_id = str(decoded_refresh_access["user_id"])
    refresh_access_scope = str(decoded_refresh_access["scope"])

    decoded_refresh_refresh = jwt.decode(refresh_refresh, public_key, algorithms=["RS256"])
    refresh_refresh_user_id = str(decoded_refresh_refresh["user_id"])
    refresh_refresh_scope = str(decoded_refresh_refresh["scope"])

    assert signup_access_user_id == refresh_access_user_id
    assert signup_access_scope == refresh_access_scope

    assert signup_refresh_user_id == refresh_refresh_user_id
    assert signup_refresh_scope == refresh_refresh_scope

    # Check the expiry times
    assert access_token_expiry <= decoded_refresh_access["exp"] <= generate_access_token_expiry()
    assert refresh_token_expiry <= decoded_refresh_refresh["exp"] <= generate_refresh_token_expiry()


# Test failure if no token provided
def test_refresh_no_token(client):
    response = client.post("/auth/refresh")
    assert response.status_code == 401


# Test failure if token scope is invalid
def test_refresh_invalid_scope(client):
    response = client.post("/auth/signup", json={"email": "test@test.com", "password": "test"})
    assert response.status_code == 200
    signup_access = response.json["access_token"]

    response = client.post("/auth/refresh", headers={"Authorization": f"Bearer {signup_access}"})
    assert response.status_code == 401


# Test failure if user does not exist
def test_refresh_invalid_user(client, private_key):
    token = generate_token(private_key, "112233445566778899aabbcc", "refresh", generate_refresh_token_expiry())

    response = client.post("/auth/refresh", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


# Test failure if a revoked token is provided
def test_refresh_revoked_token(client):
    # Signup the user
    response = client.post("/auth/signup", json={"email": "test@test.com", "password": "test"})
    assert response.status_code == 200
    signup_refresh = response.json["refresh_token"]

    # Wait 1s so that the next token is not the same as the previous one
    time.sleep(1)

    # Refresh the tokens
    response = client.post("/auth/refresh", headers={"Authorization": f"Bearer {signup_refresh}"})
    assert response.status_code == 200

    # Try and refresh again using the same refresh token
    response = client.post("/auth/refresh", headers={"Authorization": f"Bearer {signup_refresh}"})
    assert response.status_code == 401


# Test failure if token expired
def test_refresh_expired_token(client, public_key, private_key):
    # Signup the user
    response = client.post("/auth/signup", json={"email": "test@test.com", "password": "test"})
    assert response.status_code == 200
    signup_refresh = response.json["refresh_token"]

    decoded_signup_refresh = jwt.decode(signup_refresh, public_key, algorithms=["RS256"])
    signup_refresh_user_id = str(decoded_signup_refresh["user_id"])

    # Generate a token that has already expired
    token = generate_token(private_key, signup_refresh_user_id, "refresh", generate_token_expiry_in_past())

    # Try and refresh using the expired token
    response = client.post("/auth/refresh", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401