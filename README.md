# com3014_auth

Authentication server for image sharing app

## Overview
This service handles the following functions:
- Registering new user accounts
- Sign in using email and password for authentication
- Handing out access tokens and refresh tokens
- Validation of refresh tokens against the database

## Usage
Ensuring that `docker` and `docker compose` are configured on your system, run `docker compose up` from within the root of the repository. If you get an error, you may need to use `sudo docker compose up`

Once the service is running, it can be accessed at `localhost:5000`

## Token format
Both access and refresh tokens are JWT tokens signed using the secret key in `.env`. Once decoded, they have the following format:

```
{
    "user_id": "<string representation of ObjectId used to identify the user>",
    "scope": "<scope>"
}
```

Currently, the valid scopes are `"access"` and `"refresh"`. Access tokens can be used to authenticate other services, but have a very short expiry time. Refresh have a much longer expiry time but should not be used for authentication, instead they should be used to request new access tokens once they have expired.

Tokens can be included in HTTP requests by setting the `Authorization` header to `Bearer <token>`

See `/auth_server/auth_middleware.py` for an example of how authentication using the access token can be achieved.

## Interface
This is the current interface for interacting with the service:

### POST /auth/signup
Register a new account. The request body must contain the following JSON:
```
{
    "email": "<email address>",
    "password": "<password>"
}
```

The password will be stored securely as a salted hash.

If the email is already in use, an error will be returned.

On success, the following response will be received:
```
{
    "access_token": "<access_token>",
    "refresh_token": "<refresh_token>"
}
```


### POST /auth/login
Login to an account that has already been created. The request body must contain the following JSON:
```
{
    "email": "<email address>",
    "password": "<password>"
}
```

If any of the details are incorrect, an error will be returned.

On success, the following response will be received:
```
{
    "access_token": "<access_token>",
    "refresh_token": "<refresh_token>"
}
```

### POST /auth/logout
Log the current user out. This works by invalidating the user's refresh token on the server side, so it cannot be used to request new access tokens and the user must log in using their email and password again.

If the user's access token is unexpired, it will still be usable until its expiry, however the only way this could be avoided would be to have services authenticate each individual request with the authentication server, which is inefficient.

After making a request to this endpoint, the client should discard any local copies of the access and refresh tokens.

The `Authorization` header must contain `Bearer <access_token>` 

### POST /auth/refresh
Provide a valid refresh token to obtain a new access token.

The refresh token is also updated, so that it does not expire and force the user to log in again unless they have not interacted with the app in a long time.

The `Authorization` header must contain `Bearer <refresh_token>` 

On success, the following response will be received:
```
{
    "access_token": "<access_token>",
    "refresh_token": "<refresh_token>"
}
```