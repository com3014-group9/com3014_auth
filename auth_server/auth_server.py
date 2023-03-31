import bcrypt, jwt, os, traceback
from datetime import datetime, timezone, timedelta
from flask import Flask, Blueprint, request, g, current_app
from pymongo import MongoClient, errors
from bson import ObjectId

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from auth_middleware import auth_required

ACCESS_TOKEN_EXPIRY_MINUTES = 5
REFRESH_TOKEN_EXPIRY_MINUTES = (24 * 60)

# Load MongoDB credentials from environment
MONGO_USERNAME = os.environ.get("MONGO_USERNAME")
MONGO_PASSWORD = os.environ.get("MONGO_PASSWORD")

# Auth server blueprint
auth = Blueprint('auth', __name__, url_prefix='/auth')


# Setup Flask application
def create_app():
    app = Flask(__name__)
    app.register_blueprint(auth)

    # Disconnect from db on app context teardown
    app.teardown_appcontext_funcs.append(close_db)
    
    # Load public and private keys
    with open('jwtRS256.key.pub') as f:
        app.config["PUBLIC_KEY"] = f.read()

    # Loading the private key into an RSAPrivateKey object saves CPU time (PyJWT docs)
    with open('jwtRS256.key') as f:
        app.config["PRIVATE_KEY"] = serialization.load_pem_private_key(
            f.read().encode("utf8"), password=None, backend=default_backend()
        )

    # Make emails unique, db will reject duplicate emails
    client = db_open()
    client.auth_db.users.create_index("email", unique=True)
    client.close()
    
    return app


# Open a connection to the database
def db_open():
    client = MongoClient(f"mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@auth-db:27017/?authSource=admin")
    return client


# Connect to the db and store the connection in application context, return a handle to auth_db database
def get_db():
    if 'db' not in g:
        g.db = db_open()
    
    return g.db.auth_db


# Disconnect from DB if we are connected
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


# Generate access token containing user id
# Converts user id from ObjectId to string
# Expires after 5 minutes
def generate_access_token(user_id: ObjectId):
    dt = datetime.now(tz=timezone.utc)
    td = timedelta(minutes=ACCESS_TOKEN_EXPIRY_MINUTES)

    return jwt.encode(
        {"exp": dt + td, "user_id": str(user_id), "scope": "access"},
        current_app.config["PRIVATE_KEY"],
        algorithm="RS256"
    )


# Generate refresh token that will be stored in the DB and checked when a new access token is requested
# Converts user id from ObjectId to string
# Expires after 24 hours
def generate_refresh_token(user_id: ObjectId):
    dt = datetime.now(tz=timezone.utc)
    td = timedelta(minutes=REFRESH_TOKEN_EXPIRY_MINUTES)

    return jwt.encode(
        {"exp": dt + td, "user_id": str(user_id), "scope": "refresh"},
        current_app.config["PRIVATE_KEY"],
        algorithm="RS256"
    )


# Generate and return as a response the access and refresh tokens
# Store the refresh token in the database
def return_tokens_from_request(user_id: ObjectId):
    refresh_token = generate_refresh_token(user_id)
    get_db().users.update_one({"_id": user_id}, {"$set": {"refresh_token": refresh_token}})
    return {
        "access_token": generate_access_token(user_id),
        "refresh_token": refresh_token
    }, 200


# Get the public key used to decrypt JWT tokens
@auth.route("/get-public-key", methods=["POST"])
def get_public_key():
    return {
        "public_key": current_app.config["PUBLIC_KEY"]
    }, 200


# Get a new access token given a refresh token
@auth.route("/refresh", methods=["POST"])
def refresh():    
    # Decode refresh token from request header
    encoded = None
    decoded = {}
    user_id = None
    scope = None

    if "Authorization" in request.headers:
        encoded = request.headers["Authorization"].split(" ")[1]

    if not encoded:
        return {
            "message": "Missing refresh token in Authorization header",
            "error": "Unauthorized"
        }, 401 

    try:
        decoded = jwt.decode(encoded, current_app.config["PUBLIC_KEY"], algorithms=["RS256"])
        user_id = str(decoded["user_id"])
        scope = str(decoded["scope"])

    except jwt.exceptions.ExpiredSignatureError:
        return {
            "message": "Refresh token expired, log in again",
            "error": "Unauthorized"
        }, 401
    
    except Exception:
        traceback.print_exc()
        return {
            "message": "Error processing refresh token, possibly malformed",
            "error": "Unauthorized"
        }, 401
    
    # Check this is a refresh token
    if scope != "refresh":
        return {
            "message": "Invalid token scope",
            "error": "Unauthorized"
        }, 401

    # Get user associated with token
    user = get_db().users.find_one({"_id": ObjectId(user_id)})
    if user is None:
        return {
            "message": "User does not exist",
            "error": "Unauthorized"
        }, 401
    
    # Check that the token we received is the same as the one stored in the DB
    if user["refresh_token"] != encoded:
        return {
            "message": "Refresh token mismatch",
            "error": "Unauthorized"
        }, 401 
    
    # Generate new access and refresh tokens
    return return_tokens_from_request(user["_id"])


# Create a new user and log them in
@auth.route("/signup", methods=["POST"])
def signup():
    # Get JSON data from request body
    data = request.json
    if not data:
        return {
            "message": "Missing JSON data from request body",
            "error": "Bad request"
        }, 400
    
    # Get email and password
    email = ""
    password = ""
    try:
        email = str(data["email"])
        password = str(data["password"])
    
    except Exception:
        traceback.print_exc()
        return {
            "message": "Error parsing JSON body, possibly malformed",
            "error": "Bad request"
        }, 400
    
    # Check email and password are not empty
    if email == "" or password == "":
        return {
            "message": "Email or password was blank",
            "error": "Bad request"
        }, 400

    # Attempt to insert user into DB
    # Password is stored as a salted hash
    result = None
    try:
        result = get_db().users.insert_one({
            "email": email,
            "password_hash": bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt())
        })
    
    # Email is already in use
    except errors.DuplicateKeyError:
        return {
            "message": f"{email} is already registered to an account",
            "error": "Conflict"
        }, 409

    # User created, generate access and refresh tokens
    return return_tokens_from_request(result.inserted_id)


# Log user in
@auth.route("/login", methods=["POST"])
def login():
    # Get JSON data from request body
    data = request.json
    if not data:
        return {
            "message": "Missing JSON data from request body",
            "error": "Bad request"
        }, 400
    
    # Get email and password
    email = ""
    password = ""
    try:
        email = str(data["email"])
        password = str(data["password"])

    except Exception:
        traceback.print_exc()
        return {
            "message": "Error parsing JSON body, possibly malformed",
            "error": "Bad request"
        }, 400

    # Get password hash from DB and check using bcrypt
    user = get_db().users.find_one({"email": email})
    if user is None:
        return {
            "message": "User does not exist",
            "error": "Unauthorized"
        }, 401
     
    if not bcrypt.checkpw(password.encode("utf8"), user["password_hash"]):
        return {
            "message": "Incorrect password",
            "error": "Unauthorized"
        }, 401

    # Password matched, generate access and refresh tokens
    return return_tokens_from_request(user["_id"])


# Log user out by invalidating their refresh token, meaning they must log in again to get new access tokens
# The client should discard its access and refresh tokens after calling this
# The access token will still be valid until it expires, but this is mitigated by the short expiry times
@auth.route("/logout", methods=["POST"])
@auth_required
def logout(user_id: str):
    # Check user exists
    user = get_db().users.find_one({"_id": ObjectId(user_id)})
    if user is None:
        return {
            "message": "User does not exist",
            "error": "Unauthorized"
        }, 401
    
    # Invalidate refresh token by changing it to "revoked"
    # This will cause future refresh() calls to fail until a new token is generated via login()
    get_db().users.update_one({"_id": ObjectId(user_id)}, {"$set": {"refresh_token": "revoked"}})

    return {
        "message": "Successfully logged out"
    }, 200


# Handle 404 error
@auth.errorhandler(404)
def page_not_found(e):
    return "The page requested does not exist", 404
