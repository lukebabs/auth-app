import sqlite3
from werkzeug.security import generate_password_hash

def initialize_database():
    try:
        conn = sqlite3.connect("users.db")
        conn.execute("SELECT 1 FROM users LIMIT 1;")
    except sqlite3.OperationalError:
        create_users_table()
        insert_users()
    finally:
        conn.close()

def create_users_table():
    conn = sqlite3.connect("users.db")
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
    conn.commit()
    conn.close()

def insert_users():
    conn = sqlite3.connect("users.db")
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("adminalien", generate_password_hash("123webco321")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("user1001", generate_password_hash("123webco321")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("user1002", generate_password_hash("123webco321")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("user1003", generate_password_hash("123webco321")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("user1004", generate_password_hash("123webco321")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("user1005", generate_password_hash("123webco321")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("user1006", generate_password_hash("123webco321")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("user1007", generate_password_hash("123webco321")))
    return conn.commit()
