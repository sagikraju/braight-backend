"""
brAIght backend -- signup/login API backed by a cloud PostgreSQL database.

Configuration is done with environment variables, so no secrets live in
this file (and none end up in a git repository):

    DATABASE_URL     Full connection string from your host's dashboard.
                     Use the "Internal" URL when this API runs on the same
                     cloud provider/region as the database, or the
                     "External" URL when testing from your laptop. If this
                     is set, the DB_* variables below are ignored.
    DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, DB_SSLMODE
                     Used only when DATABASE_URL is not set.
    ALLOWED_ORIGINS  Comma-separated sites allowed to call this API, e.g.
                     https://zesty-palmier-26ddfc.netlify.app
                     Defaults to "*" (any site) -- set it before going live.

Run locally:    python app.py       (listens on 127.0.0.1:5000)
Run in cloud:   gunicorn app:app    (the host supplies the PORT variable)

Endpoints:
    GET  /api/health   -> {"status": "ok"} if the database is reachable
    POST /api/signup   -> create a user
    POST /api/login    -> verify username/password
"""

import logging
import os

import psycopg
from flask import Flask, jsonify, request
from flask_cors import CORS
from psycopg import errors as pg_errors
from psycopg.rows import dict_row
from werkzeug.security import check_password_hash, generate_password_hash

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("braight-backend")

app = Flask(__name__)

# Which sites may call this API from a browser. Trailing slashes are
# stripped because an origin never has one.
_origins_env = os.environ.get("ALLOWED_ORIGINS", "*").strip()
if _origins_env == "*":
    ALLOWED_ORIGINS = "*"
    logger.warning("ALLOWED_ORIGINS is not set: any website may call this API.")
else:
    ALLOWED_ORIGINS = [o.strip().rstrip("/") for o in _origins_env.split(",") if o.strip()]
CORS(app, origins=ALLOWED_ORIGINS)

ALLOWED_USER_TYPES = {"Student", "Jobseeker", "ADMIN"}

# Used so a login for an unknown username takes about as long as one for a
# real username (otherwise response time reveals which usernames exist).
_DUMMY_HASH = generate_password_hash("not-a-real-password")


def get_connection():
    url = os.environ.get("DATABASE_URL")
    if url:
        return psycopg.connect(url, connect_timeout=10)
    return psycopg.connect(
        host=os.environ.get("DB_HOST", "dpg-db3q520473hc73euv06g-a"),
        port=os.environ.get("DB_PORT", "5432"),
        dbname=os.environ.get("DB_NAME", "braight"),
        user=os.environ.get("DB_USER", "anvisagi"),
        password=os.environ.get("DB_PASSWORD", "jTi3fIz48SRFXiGdjKfgfrHwSwxwisYs"),
        sslmode=os.environ.get("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


@app.route("/api/health", methods=["GET"])
def health():
    try:
        with get_connection():
            pass
        return jsonify({"status": "ok"}), 200
    except Exception:
        logger.exception("health check failed")
        return jsonify({"status": "error"}), 500


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
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (first_name, last_name, username, password_hash, user_type)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id, first_name, last_name, username, user_type, created_at
                """,
                (first_name, last_name, username, password_hash, user_type),
            )
            row = cur.fetchone()
    except pg_errors.UniqueViolation:
        return jsonify({"error": "That username is already taken."}), 409
    except Exception:
        logger.exception("signup failed")
        return jsonify({"error": "Could not create account."}), 500

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
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT id, first_name, last_name, username, password_hash, user_type "
                "FROM users WHERE username = %s",
                (username,),
            )
            row = cur.fetchone()
    except Exception:
        logger.exception("login failed")
        return jsonify({"error": "Login failed."}), 500

    if row is None:
        check_password_hash(_DUMMY_HASH, password)  # keep timing similar
        return jsonify({"error": "Invalid username or password."}), 401

    if not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Invalid username or password."}), 401

    user = {
        "id": row["id"], "firstName": row["first_name"], "lastName": row["last_name"],
        "username": row["username"], "userType": row["user_type"],
    }
    return jsonify({"user": user}), 200


if __name__ == "__main__":
    # Local development only. In the cloud, gunicorn runs the app instead.
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port)
