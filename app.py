from flask import Flask, render_template, request, redirect, url_for, session, g
import sqlite3
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
from sqllite_create import initialize_database
import jwt
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "default-secret")

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
            token = jwt.encode({"user": username}, os.environ["JWT_SECRET"], algorithm="HS256")
            session["token"] = token
            return redirect(url_for("dashboard"))
            # return redirect(f"https://bluefish.impvdemo.com?token={token}")  # 🔁 External redirect
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
