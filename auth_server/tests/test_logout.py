# Since logout is guarded by @auth_required, these tests also test auth_middleware.py
import jwt
from conftest import generate_token, generate_access_token_expiry, generate_token_expiry_in_past

# Test logging out a signed in user
def test_logout(client):
    # Sign up the user
    response = client.post("/auth/signup", json={"email": "test@test.com", "password": "test"})
    assert response.status_code == 200
    signup_access = response.json["access_token"]
    signup_refresh = response.json["refresh_token"]

    # Log out the user
    response = client.post("/auth/logout", headers={"Authorization": f"Bearer {signup_access}"})
    assert response.status_code == 200

    # Test that we can no longer use the refresh token
    response = client.post("/auth/refresh", headers={"Authorization": f"Bearer {signup_refresh}"})
    assert response.status_code == 401


# Test failure if user does not exist
def test_logout_invalid_user(client, private_key):
    token = generate_token(private_key, "112233445566778899aabbcc", "access", generate_access_token_expiry())

    response = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


# Test failure if missing Authorization header
def test_logout_missing_header(client):
    response = client.post("/auth/logout")
    assert response.status_code == 401


# Test failure if token expired
def test_logout_expired_token(client, public_key, private_key):
    # Signup the user
    response = client.post("/auth/signup", json={"email": "test@test.com", "password": "test"})
    assert response.status_code == 200
    signup_access = response.json["access_token"]

    decoded_signup_access = jwt.decode(signup_access, public_key, algorithms=["RS256"])
    signup_access_user_id = str(decoded_signup_access["user_id"])

    # Generate a token that has already expired 
    token = generate_token(private_key, signup_access_user_id, "access", generate_token_expiry_in_past())

    # Try and logout using the expired token
    response = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


# Test failure if token scope is invalid
def test_logout_invalid_scope(client):
    # Signup the user
    response = client.post("/auth/signup", json={"email": "test@test.com", "password": "test"})
    assert response.status_code == 200
    signup_refresh = response.json["refresh_token"]

    # Try and logout using the refresh token instead of the access token
    response = client.post("/auth/logout", headers={"Authorization": f"Bearer {signup_refresh}"})
    assert response.status_code == 401


# Test failure if user_id is blank
def test_logout_blank_user_id(client, private_key):
    token = generate_token(private_key, "", "access", generate_access_token_expiry())
    response = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
