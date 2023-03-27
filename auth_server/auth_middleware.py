import jwt, traceback
from functools import wraps
from flask import request, current_app

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Decode token from request header
        encoded = None
        decoded = {}
        user_id = None
        scope = None
        if "Authorization" in request.headers:
            encoded = request.headers["Authorization"].split(" ")[1]

        if not encoded:
            return {
                "message": "Missing access token in Authorization header",
                "error": "Unauthorized"
            }, 401
        
        try:
            decoded = jwt.decode(encoded, current_app.config["SECRET_KEY"], algorithms=["HS256"])
            user_id = str(decoded["user_id"])
            scope = str(decoded["scope"])

        except jwt.exceptions.ExpiredSignatureError:
            return {
                "message": "Access token expired, please refresh",
                "error": "Unauthorized"
            }, 401
        
        except Exception:
            traceback.print_exc()
            return {
                "message": "Error processing access token, possibly malformed",
                "error": "Unauthorized"
            }, 401
        
        if not user_id:
            return {
                "message": "user_id was None",
                "error": "Unauthorized"
            }, 401
        
        if scope != "access":
            return {
                "message": "Invalid token scope",
                "error": "Unauthorized"
            }, 401
        
        # Pass user_id to decorated function
        return f(user_id , *args, **kwargs)
    
    return decorated