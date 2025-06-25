from flask import Flask, request, jsonify
import os, jwt
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("JWT_SECRET")
JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is not set")

LOG_PATH = "logs/login_events.log"

@app.route("/log", methods=["POST"])
def log_event():
    data = request.json or {}
    timestamp = datetime.utcnow().isoformat()
    username = data.get("username", "unknown")
    ip = data.get("ip", "unknown")
    token_hash = hash(data.get("token", ""))

    log_line = f"[{timestamp}] LOGIN - user: {username} - ip: {ip} - token_hash: {token_hash}"

    if os.environ.get("LOG_TO_FILE", "true") == "true":
        os.makedirs("logs", exist_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(log_line + "\n")

    print(log_line)
    return {"status": "logged"}, 200

@app.route("/logs", methods=["GET"])
def get_logs():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid token"}), 401

    token = auth_header.split(" ")[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        username = decoded.get("user")
    except jwt.InvalidTokenError as e:
        return jsonify({"error": f"Invalid token: {str(e)}"}), 401

    if username != "adminalien":
        return jsonify({"error": "Not authorized"}), 403

    try:
        with open(LOG_PATH, "r") as f:
            logs = f.readlines()
    except FileNotFoundError:
        logs = ["[No logs available]"]

    logs = logs[::-1]
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    paginated = logs[(page - 1) * per_page: page * per_page]

    return jsonify({
        "logs": paginated,
        "page": page,
        "total": len(logs),
        "total_pages": (len(logs) + per_page - 1) // per_page
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5001)))
# logger/logger_service.py
# SE Demo only
# This file implements a simple Flask service to log user login events and retrieve logs.
# It uses JWT for authentication and stores logs in a file.
# The service provides endpoints to log events and retrieve logs with pagination.
# This service is designed to be run independently and can be integrated with other applications.
# It requires the JWT_SECRET environment variable to be set for token validation.
# Ensure you have Flask and PyJWT installed:
# pip install Flask PyJWT python-dotenv
# Usage:
# 1. Set the JWT_SECRET environment variable:
