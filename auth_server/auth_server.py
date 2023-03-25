import bcrypt, jwt, os, pprint
from flask import Flask, request, redirect, jsonify
from pymongo import MongoClient

# This is the secret key used to encrypt and decrypt the JWT
# In a production environment, it should not be hardcoded into the app like this
# TODO look into docker secrets
SECRET_KEY = "test secret"  

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

# Setup DB connection
client = MongoClient("mongodb://auth-db:27017")
auth_db = client.auth_db

# Make emails unique
auth_db.users.create_index("email", unique=True)


# Create a new user and log them in
@app.route("/auth/signup", methods=["POST"])
def signup():
    # Get JSON data from request body
    data = request.json
    if not data:
        return {
            "message": "Missing JSON data from request body",
            # "data": None,
            # "error": "Bad request"
        }, 400
    
    # Get email and password
    email = data.get("email")
    password = data.get("password")

    # Attempt to insert user into DB
    # Password is stored as a salted hash
    result = auth_db.users.insert_one({"email": email, "password": bcrypt.hashpw(password, bcrypt.gensalt())})
    # if not result.acknowledged:

    pprint(result)
        

    # User created, generate and return JWT
    return {
        "data": {"user_id": result.inserted_id},
    }, 200

# Log user in
@app.route("/auth/login", methods=["POST"])
def login():
    # Get JSON data from request body
    data = request.json
    if not data:
        return {
            "message": "Missing JSON data from request body",
            # "data": None,
            # "error": "Bad request"
        }, 400
    
    # Get email and password
    email = data.get("email")
    password = data.get("password")
    
    # TODO validate inputs

    # Get password hash from DB and check using bcrypt
    user = auth_db.users.find_one({"email": email})
    if user is None:
        return {
            "message": "User does not exist",
            # "data": None,
            # "error": "Unauthorized"
        }, 401
     
    if not bcrypt.checkpw(password, user["password_hash"]):
        return {
            "message": "Incorrect password",
            # "data": None,
            # "error": "Unauthorized"
        }, 401

    # Password matched, generate and return JWT
    print(f"logged in as {user['_id']}")

    return {
        "data": {"user_id": user["_id"]},
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

# # Main entrypoint
# if __name__ == "__main__":
    

#     # Run flask app
#     app.run(debug=True)
