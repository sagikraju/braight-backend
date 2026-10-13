"""
brAIght backend -- signup/login API backed by PostgreSQL.

Required environment:
  DATABASE_URL (recommended for Render), or DB_HOST, DB_PORT, DB_NAME,
  DB_USER, DB_PASSWORD and optionally DB_SSLMODE.
  ALLOWED_ORIGINS: comma-separated allowed frontend origins.

Run locally: python app.py
Render start command: gunicorn app:app
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

_origins_env = os.environ.get(
    "ALLOWED_ORIGINS",
    "https://braight.in,https://www.braight.in,https://zesty-palmier-26ddfc.netlify.app"
).strip()
ALLOWED_ORIGINS = [o.strip().rstrip("/") for o in _origins_env.split(",") if o.strip()]
CORS(app, origins=ALLOWED_ORIGINS)

# ADMIN accounts can still log in if already present, but public signup is
# restricted to Student and Jobseeker.
ALLOWED_SIGNUP_TYPES = {"Student", "Jobseeker"}
MAX_FAILED_ATTEMPTS = 3
INACTIVE_AFTER_DAYS = 60
_DUMMY_HASH = generate_password_hash("not-a-real-password")


def get_connection():
    """Use the cloud provider's connection URL, or individual env vars."""
    url = os.environ.get("DATABASE_URL")
    if url:
        return psycopg.connect(url, connect_timeout=10)

    # No database credentials are hard-coded in this source file.
    required = ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise RuntimeError("Missing database environment variable(s): " + ", ".join(missing))

    kwargs = {
        "host": os.environ["DB_HOST"],
        "port": os.environ.get("DB_PORT", "5432"),
        "dbname": os.environ["DB_NAME"],
        "user": os.environ["DB_USER"],
        "password": os.environ["DB_PASSWORD"],
        "connect_timeout": 10,
    }
    sslmode = os.environ.get("DB_SSLMODE")
    if sslmode:
        kwargs["sslmode"] = sslmode
    return psycopg.connect(**kwargs)


@app.route("/api/health", methods=["GET"])
def health():
    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
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
    if user_type not in ALLOWED_SIGNUP_TYPES:
        return jsonify({"error": "User type must be Student or Jobseeker."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    password_hash = generate_password_hash(password)
    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users
                    (first_name, last_name, username, password_hash, user_type, status,
                     failed_login_attempts)
                VALUES (%s, %s, %s, %s, %s, 'active', 0)
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
        "id": row[0],
        "firstName": row[1],
        "lastName": row[2],
        "username": row[3],
        "userType": row[4],
        "createdAt": row[5].isoformat(),
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
        # Lock this user's row while checking/updating the attempt counter,
        # so simultaneous failed attempts cannot bypass the three-attempt limit.
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT id, first_name, last_name, username, password_hash, user_type,
                       status, last_login, created_at, failed_login_attempts
                FROM users
                WHERE username = %s
                FOR UPDATE
                """,
                (username,),
            )
            row = cur.fetchone()

            if row is None:
                check_password_hash(_DUMMY_HASH, password)
                return jsonify({"error": "Invalid username or password."}), 401

            status = (row["status"] or "").strip().lower()
            if status == "locked":
                return jsonify({"error": "Your account is locked after three unsuccessful login attempts. Please contact the administrator."}), 403
            if status == "inactive":
                return jsonify({"error": "Your account is inactive because there has been no activity for 60 days. Please contact the administrator."}), 403
            if status != "active":
                return jsonify({"error": "Your account is not active. Please contact the administrator."}), 403

            # If the account has never logged in, use created_at as the last
            # activity reference; otherwise use last_login.
            cur.execute(
                """
                SELECT COALESCE(%s::timestamptz, %s::timestamptz)
                       < NOW() - (%s * INTERVAL '1 day') AS is_inactive
                """,
                (row["last_login"], row["created_at"], INACTIVE_AFTER_DAYS),
            )
            is_inactive = cur.fetchone()["is_inactive"]
            if is_inactive:
                cur.execute("UPDATE users SET status = 'inactive' WHERE id = %s", (row["id"],))
                return jsonify({"error": "Your account is inactive because there has been no activity for 60 days. Please contact the administrator."}), 403

            if not check_password_hash(row["password_hash"], password):
                attempts = int(row["failed_login_attempts"] or 0) + 1
                if attempts >= MAX_FAILED_ATTEMPTS:
                    cur.execute(
                        "UPDATE users SET failed_login_attempts = %s, status = 'locked' WHERE id = %s",
                        (attempts, row["id"]),
                    )
                    return jsonify({"error": "Your account has been locked after three unsuccessful login attempts. Please contact the administrator."}), 403
                cur.execute(
                    "UPDATE users SET failed_login_attempts = %s WHERE id = %s",
                    (attempts, row["id"]),
                )
                remaining = MAX_FAILED_ATTEMPTS - attempts
                return jsonify({"error": f"Invalid username or password. {remaining} attempt(s) remaining before the account is locked."}), 401

            cur.execute(
                """
                UPDATE users
                SET last_login = NOW(), failed_login_attempts = 0
                WHERE id = %s
                """,
                (row["id"],),
            )

            user = {
                "id": row["id"],
                "firstName": row["first_name"],
                "lastName": row["last_name"],
                "username": row["username"],
                "userType": row["user_type"],
            }
        return jsonify({"user": user}), 200
    except Exception:
        logger.exception("login failed")
        return jsonify({"error": "Login failed."}), 500


@app.route("/api/change-password", methods=["POST"])
def change_password():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    old_password = data.get("oldPassword") or ""
    new_password = data.get("newPassword") or ""

    if not username or not old_password or not new_password:
        return jsonify({"error": "All fields are required."}), 400
    if len(new_password) < 8:
        return jsonify({"error": "New password must be at least 8 characters."}), 400
    if new_password == old_password:
        return jsonify({"error": "New password must be different from the current one."}), 400

    try:
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT password_hash FROM users WHERE username = %s FOR UPDATE",
                (username,),
            )
            row = cur.fetchone()
            if row is None:
                check_password_hash(_DUMMY_HASH, old_password)
                valid = False
            else:
                valid = check_password_hash(row["password_hash"], old_password)
            if valid:
                cur.execute(
                    "UPDATE users SET password_hash = %s WHERE username = %s",
                    (generate_password_hash(new_password), username),
                )
    except Exception:
        logger.exception("change-password failed")
        return jsonify({"error": "Could not change password."}), 500

    if not valid:
        return jsonify({"error": "Username or current password is incorrect."}), 401
    return jsonify({"message": "Password changed."}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=False)
