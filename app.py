from flask import Flask, render_template, request, redirect, url_for, session, g, Response
import sqlite3
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
from sqllite_create import initialize_database
import jwt
import os
import requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("JWT_SECRET")
JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is not set")
LOGGER_URL = os.environ.get("LOGGER_URL")

DATABASE = "users.db"
initialize_database()

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and check_password_hash(user[2], password):  # user[2] is password_hash
            session["user"] = username
            # Generate JWT token
            token = jwt.encode({"user": username}, JWT_SECRET, algorithm="HS256")
            if isinstance(token, bytes):  # PyJWT 1.x behavior
                token = token.decode("utf-8")
            session["token"] = token
            try:
                requests.post(LOGGER_URL, json={
                    "username": username,
                    "ip": request.remote_addr,
                    "token": token
                })
            except Exception as e:
                print(f"Failed to log login event: {e}")
            return redirect(url_for("dashboard"))
            # return redirect(f"https://bluefish.impvdemo.com?token={token}")  # External redirect
        else:
            return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["user"], token=session.get("token", ""))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/logs")
def view_logs():
    if "token" not in session:
        return redirect(url_for("login"))

    page = int(request.args.get("page", 1))
    try:
        response = requests.get(
            os.environ.get("LOGGER_URL") + "/logs",
            params={"page": page, "per_page": 20},
            headers={"Authorization": f"Bearer {session['token']}"},
            timeout=3
        )
        data = response.json()
        logs = data.get("logs", [])
        total_pages = data.get("total_pages", 1)
    except Exception as e:
        print(f"[ERROR] Failed to fetch logs: {e}")
        logs = ["[Unable to retrieve logs]"]
        total_pages = 1

    return render_template("logs.html", logs=logs, page=page, total_pages=total_pages)

@app.route("/logs/stream")
def stream_logs_page():
    if "token" not in session:
        return redirect(url_for("login"))
    return render_template("stream.html", token=session["token"])

@app.route("/logs/stream-proxy")
def view_logs_stream_proxy():
    if "token" not in session:
        return "Unauthorized", 401

    def generate():
        headers = {"Authorization": f"Bearer {session['token']}"}
        with requests.get(
            os.environ["LOGGER_URL"].replace("/log", "/stream"),
            headers=headers,
            stream=True,
        ) as r:
            for line in r.iter_lines():
                if line:
                    yield line.decode("utf-8") + "\n"

    return Response(generate(), mimetype="text/event-stream")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
