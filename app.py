from flask import Flask, render_template, request, redirect, url_for, session, g, Response
import sqlite3
from werkzeug.security import check_password_hash, generate_password_hash
from sqllite_create import initialize_database
import jwt
import os
import requests
import hashlib
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
JWT_SECRET = os.environ.get("JWT_SECRET")
LOGGER_URL = os.environ.get("LOGGER_URL")
EXPERIMENT_ID = os.environ.get("EXPERIMENT_ID", "exp-default")

if not JWT_SECRET or not LOGGER_URL:
    raise RuntimeError("JWT_SECRET and LOGGER_URL must be set")

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

def assign_ab_group(username):
    return "A" if int(hashlib.md5(username.encode()).hexdigest(), 16) % 2 == 0 else "B"

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and check_password_hash(user[2], password):
            session["user"] = username
            group = assign_ab_group(username)
            session["ab_group"] = group
            session["experiment_id"] = EXPERIMENT_ID

            token = jwt.encode({"user": username}, JWT_SECRET, algorithm="HS256")
            if isinstance(token, bytes):
                token = token.decode("utf-8")
            session["token"] = token

            try:
                requests.post(f"{LOGGER_URL}/log", json={
                    "username": username,
                    "ip": request.remote_addr,
                    "token": token,
                    "group": group,
                    "experiment_id": EXPERIMENT_ID
                })
            except Exception as e:
                print(f"Failed to log login event: {e}")

            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    group = session.get("ab_group", "A")
    return render_template(f"dashboard_{group.lower()}.html", user=session["user"], token=session.get("token", ""))

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
            f"{LOGGER_URL}/logs",
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

    token = session["token"]

    def generate():
        headers = {"Authorization": f"Bearer {token}"}
        with requests.get(
            f"{LOGGER_URL}/stream",
            headers=headers,
            stream=True
        ) as r:
            for line in r.iter_lines():
                if line:
                    yield line.decode("utf-8") + "\n"

    return Response(generate(), mimetype="text/event-stream")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
