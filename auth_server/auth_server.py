import bcrypt, jwt, os
from flask import Flask, request, redirect, jsonify
from pymongo import MongoClient, errors

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get('SECRET_KEY')

# Setup DB connection
client = MongoClient("mongodb://auth-db:27017")
auth_db = client.auth_db

# Make emails unique
auth_db.users.create_index("email", unique=True)


# Generate JWT containing user id
# Converts user id from ObjectId to string
def generate_jwt(user_id):
    return jwt.encode({"user_id": str(user_id)}, app.config["SECRET_KEY"], algorithm="HS256")


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
        result = auth_db.users.insert_one({"email": email, "password_hash": bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt())})
    
    # Duplicate email
    except errors.DuplicateKeyError:
        return {
            "message": f"{email} is already registered to an account",
            "error": "Bad request"
        }, 400

    # User created, generate and return JWT
    return {
        "jwt": generate_jwt(result.inserted_id)
    }, 200


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

    # Password matched, generate and return JWT
    return {
        "jwt": generate_jwt(user["_id"])
    }, 200

# Log user out
@app.route("/auth/logout", methods=["POST"])
def logout():
    # TODO invalidate JWT? or could logging out just be discarding it client side?
    return

# Handle 404 error
@app.errorhandler(404)
def page_not_found(e):
    return "The page requested does not exist", 404
