"""
brAIght backend -- minimal signup/login API backed by PostgreSQL.

Setup:
    1. Create a Postgres database and run schema.sql against it (see README.md).
    2. pip install -r requirements.txt
    3. Set the DB_* environment variables below if your setup differs from
       the defaults (or just edit the defaults directly for local testing).
    4. python app.py
       The API listens on 0.0.0.0:5000, so it's reachable from other
       devices on your network at http://<your-laptop-LAN-IP>:5000.

Endpoints:
    GET  /api/health          -> {"status": "ok"} if the DB connection works
    POST /api/signup          -> create a user
    POST /api/login           -> verify username/password

This is a minimal reference implementation, not a production-hardened
service -- see the security notes in README.md before exposing it beyond
your home network.
"""

import os

import psycopg2
import psycopg2.extras
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
#CORS(app)  # Allows the static HTML pages (served from a different origin, e.g. Netlify) to call this API.
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "https://braight.in",
                "https://www.braight.in"
            ]
        }
    }
)

ALLOWED_USER_TYPES = {"Student", "Jobseeker", "ADMIN"}

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "dpg-db3q520473hc73euv06g-a"),
    "port": os.environ.get("DB_PORT", "5432"),
    "dbname": os.environ.get("DB_NAME", "braight_db"),
    "user": os.environ.get("DB_USER", "anvisagi"),
    "password": os.environ.get("DB_PASSWORD", ""),
}


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


@app.route("/api/health", methods=["GET"])
def health():
    try:
        conn = get_connection()
        conn.close()
        return jsonify({"status": "ok"}), 200
    except Exception as exc:
        return jsonify({"status": "error", "detail": str(exc)}), 500


@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or {}

    first_name = (data.get("firstName") or "").strip()
    last_name = (data.get("lastName") or "").strip()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    user_type = data.get("userType") or ""

    if not all([first_name, last_name, username, password, user_type]):
        return jsonify({"error": "All fields are required."}), 400

    if user_type not in ALLOWED_USER_TYPES:
        return jsonify({"error": "userType must be Student, Jobseeker, or ADMIN."}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    password_hash = generate_password_hash(password)

    try:
        conn = get_connection()
        with conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (first_name, last_name, username, password_hash, user_type)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id, first_name, last_name, username, user_type, created_at
                """,
                (first_name, last_name, username, password_hash, user_type),
            )
            row = cur.fetchone()
        conn.close()
    except psycopg2.errors.UniqueViolation:
        return jsonify({"error": "That username is already taken."}), 409
    except Exception as exc:
        return jsonify({"error": "Could not create account.", "detail": str(exc)}), 500

    user = {
        "id": row[0], "firstName": row[1], "lastName": row[2],
        "username": row[3], "userType": row[4], "createdAt": row[5].isoformat(),
    }
    return jsonify({"user": user}), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    try:
        conn = get_connection()
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute(
                "SELECT id, first_name, last_name, username, password_hash, user_type "
                "FROM users WHERE username = %s",
                (username,),
            )
            row = cur.fetchone()
        conn.close()
    except Exception as exc:
        return jsonify({"error": "Login failed.", "detail": str(exc)}), 500

    if row is None or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Invalid username or password."}), 401

    user = {
        "id": row["id"], "firstName": row["first_name"], "lastName": row["last_name"],
        "username": row["username"], "userType": row["user_type"],
    }
    return jsonify({"user": user}), 200


if __name__ == "__main__":
    # 0.0.0.0 so other devices on the network can reach this, not just localhost.
    app.run(host="0.0.0.0", port=5000, debug=True)
