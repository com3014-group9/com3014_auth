import bcrypt, jwt, os
from datetime import datetime, timezone, timedelta
from flask import Flask, request, redirect, jsonify
from pymongo import MongoClient, errors

ACCESS_TOKEN_EXPIRY_MINUTES = 5
REFRESH_TOKEN_EXPIRY_MINUTES = (24 * 60)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get('SECRET_KEY')

# Setup DB connection
client = MongoClient("mongodb://auth-db:27017")
auth_db = client.auth_db

# Make emails unique, db will reject duplicate emails
auth_db.users.create_index("email", unique=True)


# Generate access token containing user id
# Converts user id from ObjectId to string
# Expires after 5 minutes
def generate_access_token(user_id):
    dt = datetime.now(tz=timezone.utc)
    td = timedelta(minutes=ACCESS_TOKEN_EXPIRY_MINUTES)

    return jwt.encode(
        {"exp": dt + td, "user_id": str(user_id)},
        app.config["SECRET_KEY"],
        algorithm="HS256"
    )

# Generate refresh token that will be stored in the DB and checked when a new access token is requested
# Converts user id from ObjectId to string
# Expires after 24 hours
def generate_refresh_token(user_id):
    dt = datetime.now(tz=timezone.utc)
    td = timedelta(minutes=REFRESH_TOKEN_EXPIRY_MINUTES)

    return jwt.encode(
        {"exp": dt + td, "user_id": str(user_id)},
        app.config["SECRET_KEY"],
        algorithm="HS256"
    )

# Generate and return as a response the access and refresh tokens
# Store the refresh token in the database
def return_tokens_from_request(user_id):
    refresh_token = generate_refresh_token(user_id)
    auth_db.users.update_one({"_id": user_id}, {"refresh_token": refresh_token})
    return {
        "access_token": generate_access_token(user_id),
        "refresh_token": refresh_token
    }, 200

# Get a new access token given a refresh token
@app.route("/auth/refresh", methods=["POST"])
def refresh():
    # Get json data
    data = request.json
    if not data:
        return {
            "message": "Missing JSON data from request body",
            "error": "Bad request"
        }, 400
    
    # Decode refresh token
    encoded = str(data.get("refresh_token"))
    decoded = jwt.decode(encoded, "secret", algorithms=["HS256"])

    return return_tokens_from_request(user["_id"])

# Create a new user and log them in
@app.route("/auth/signup", methods=["POST"])
def signup():
    # Get JSON data from request body
    data = request.json
    if not data:
        return {
            "message": "Missing JSON data from request body",
            "error": "Bad request"
        }, 400
    
    # Get email and password
    email = str(data.get("email"))
    password = str(data.get("password"))

    # Attempt to insert user into DB
    # Password is stored as a salted hash
    result = None
    try:
        result = auth_db.users.insert_one({
            "email": email,
            "password_hash": bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt())
        })
    
    # Email is already in use
    except errors.DuplicateKeyError:
        return {
            "message": f"{email} is already registered to an account",
            "error": "Bad request"
        }, 400

    # User created, generate access and refresh tokens
    return return_tokens_from_request(result.inserted_id)


# Log user in
@app.route("/auth/login", methods=["POST"])
def login():
    # Get JSON data from request body
    data = request.json
    if not data:
        return {
            "message": "Missing JSON data from request body",
            "error": "Bad request"
        }, 400
    
    # Get email and password
    email = str(data.get("email"))
    password = str(data.get("password"))
    
    # TODO validate inputs

    # Get password hash from DB and check using bcrypt
    user = auth_db.users.find_one({"email": email})
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

# Log user out
@app.route("/auth/logout", methods=["POST"])
def logout():
    # TODO invalidate JWT? or could logging out just be discarding it client side?
    return

# Handle 404 error
@app.errorhandler(404)
def page_not_found(e):
    return "The page requested does not exist", 404
