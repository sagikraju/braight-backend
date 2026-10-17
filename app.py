"""
brAIght backend -- signup/login API backed by PostgreSQL.

Required environment:
  DATABASE_URL (recommended for Render), or DB_HOST, DB_PORT, DB_NAME,
  DB_USER, DB_PASSWORD and optionally DB_SSLMODE.
  ALLOWED_ORIGINS: comma-separated allowed frontend origins.

Required one-time database migration (run BEFORE deploying this file):

  ALTER TABLE users
    ADD COLUMN IF NOT EXISTS admin_session_hash TEXT,
    ADD COLUMN IF NOT EXISTS admin_session_last_active TIMESTAMPTZ;

  CREATE UNIQUE INDEX IF NOT EXISTS users_admin_session_hash_idx
    ON users (admin_session_hash) WHERE admin_session_hash IS NOT NULL;

Note: the admin_session_* columns now hold the single live session of EVERY
user (admins and regular users), despite the column names.

Run locally: python app.py
Render start command: gunicorn app:app
"""

import hashlib
import logging
import os
import secrets
from functools import wraps

import psycopg
from flask import Flask, g, jsonify, request
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
CORS(
    app,
    origins=ALLOWED_ORIGINS,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "OPTIONS"],
)

# ADMIN accounts can still log in if already present, but public signup is
# restricted to Student and Jobseeker.
ALLOWED_SIGNUP_TYPES = {"Student", "Jobseeker"}
ALLOWED_STATUS_VALUES = {"active", "inactive", "locked"}
MAX_FAILED_ATTEMPTS = 3
INACTIVE_AFTER_DAYS = 60

# Sessions (admins and regular users) are server-side and expire when idle. The
# pages log the user out after 30 s without any activity; the server allows a
# little longer (heartbeat interval + network latency) so the two never disagree.
SESSION_IDLE_TIMEOUT_SECONDS = 45

_DUMMY_HASH = generate_password_hash("not-a-real-password")


def get_connection():
    """Use the cloud provider's connection URL, or individual env vars."""
    url = os.environ.get("DATABASE_URL")
    if url:
        return psycopg.connect(url, connect_timeout=10)

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


# --------------------------------------------------------------------------
# Session helpers
# --------------------------------------------------------------------------

def _hash_token(token):
    """Only a SHA-256 hash of the session token is stored in the database."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _bearer_token():
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer":
        return ""
    return token.strip()


def _session_required(admin_only):
    """
    Build a decorator that allows the request only if it carries a valid,
    non-expired session token. Validation and the 'last active' refresh happen
    in one atomic UPDATE, so every authenticated call also keeps the session
    alive. With admin_only=True the session must also belong to an ADMIN
    account; any other user gets 403.
    """
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            token = _bearer_token()
            if not token:
                return jsonify({"error": "Authentication required.", "code": "AUTH_REQUIRED"}), 401
            try:
                with get_connection() as conn, conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE users
                        SET admin_session_last_active = NOW()
                        WHERE admin_session_hash = %s
                          AND admin_session_last_active
                              > NOW() - (%s::int * INTERVAL '1 second')
                        RETURNING username, user_type
                        """,
                        (_hash_token(token), SESSION_IDLE_TIMEOUT_SECONDS),
                    )
                    row = cur.fetchone()
            except Exception:
                logger.exception("session check failed")
                return jsonify({"error": "Could not verify session."}), 500

            if row is None:
                return jsonify({
                    "error": "Your session has timed out. Please re-login.",
                    "code": "SESSION_EXPIRED",
                }), 401

            g.session_username = row[0]
            if admin_only and (row[1] or "").strip().upper() != "ADMIN":
                return jsonify({
                    "error": "Administrator access required.",
                    "code": "FORBIDDEN",
                }), 403
            return view(*args, **kwargs)

        return wrapper
    return decorator


require_session = _session_required(False)   # any logged-in user
require_admin = _session_required(True)      # ADMIN accounts only


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
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT id, first_name, last_name, username, password_hash, user_type,
                       status, last_login, created_at, failed_login_attempts,
                       (admin_session_hash IS NOT NULL
                        AND admin_session_last_active
                            > NOW() - (%s::int * INTERVAL '1 second')) AS has_active_session
                FROM users
                WHERE username = %s
                FOR UPDATE
                """,
                (SESSION_IDLE_TIMEOUT_SECONDS, username),
            )
            row = cur.fetchone()

            if row is None:
                check_password_hash(_DUMMY_HASH, password)
                return jsonify({"error": "Invalid username or password."}), 401

            status = (row["status"] or "").strip().lower()
            user_type = (row["user_type"] or "").strip()
            is_admin = user_type.upper() == "ADMIN"

            if not is_admin:
                if status == "locked":
                    return jsonify({"error": "Your account is locked after three unsuccessful login attempts. Please contact the administrator."}), 403
                if status == "inactive":
                    return jsonify({"error": "Your account is inactive because there has been no activity for 60 days. Please contact the administrator."}), 403
                if status != "active":
                    return jsonify({"error": "Your account is not active. Please contact the administrator."}), 403

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
                        (attempts, row["id"],),
                    )
                    return jsonify({"error": "Your account has been locked after three unsuccessful login attempts. Please contact the administrator."}), 403
                cur.execute(
                    "UPDATE users SET failed_login_attempts = %s WHERE id = %s",
                    (attempts, row["id"],),
                )
                remaining = MAX_FAILED_ATTEMPTS - attempts
                return jsonify({"error": f"Invalid username or password. {remaining} attempt(s) remaining before the account is locked."}), 401

            # Password is correct. Only one live session per user: refuse a
            # second login (without touching the existing session) while the
            # first one is still active. The row is locked FOR UPDATE above,
            # so two simultaneous logins cannot both get through.
            if row["has_active_session"]:
                return jsonify({
                    "error": "This account already has an active session. "
                             "Please log out from the other session, or wait for it to time out, and try again."
                }), 409

            session_token = secrets.token_urlsafe(32)
            cur.execute(
                """
                UPDATE users
                SET last_login = NOW(), failed_login_attempts = 0,
                    admin_session_hash = %s, admin_session_last_active = NOW()
                WHERE id = %s
                """,
                (_hash_token(session_token), row["id"]),
            )

            user = {
                "id": row["id"],
                "firstName": row["first_name"],
                "lastName": row["last_name"],
                "username": row["username"],
                "userType": row["user_type"],
            }
            # Stored by Login.html together with the user object.
            user["sessionToken"] = session_token
        return jsonify({"user": user}), 200
    except Exception:
        logger.exception("login failed")
        return jsonify({"error": "Login failed."}), 500


@app.route("/api/session/heartbeat", methods=["POST"])
@app.route("/api/admin/heartbeat", methods=["POST"])  # old path, kept for pages cached before the update
@require_session
def session_heartbeat():
    # require_session has already refreshed the session's last-active time.
    return jsonify({"status": "ok"}), 200


@app.route("/api/admin/profiles", methods=["GET"])
@require_admin
def admin_list_profiles():
    """All non-admin users, for the User Profile list page."""
    try:
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT first_name, last_name, username, user_type, last_login
                FROM users
                WHERE UPPER(TRIM(user_type)) IS DISTINCT FROM 'ADMIN'
                ORDER BY id ASC
                """
            )
            users = cur.fetchall()
        for u in users:
            if u["last_login"]:
                u["last_login"] = u["last_login"].isoformat()
        return jsonify({"users": users}), 200
    except Exception:
        logger.exception("admin_list_profiles failed")
        return jsonify({"error": "Could not retrieve users."}), 500


@app.route("/api/admin/profile", methods=["GET"])
@require_admin
def admin_get_profile():
    """
    Profile of ONE selected non-admin user (?username=...). Admin accounts are
    never returned by this endpoint; they get the same 404 as an unknown user.
    """
    username = (request.args.get("username") or "").strip()
    if not username:
        return jsonify({"error": "Username is required."}), 400
    try:
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT username, first_name, last_name, status, last_login,
                       address, city
                FROM users
                WHERE username = %s
                  AND UPPER(TRIM(user_type)) IS DISTINCT FROM 'ADMIN'
                """,
                (username,),
            )
            profile = cur.fetchone()
        if profile is None:
            return jsonify({"error": "User not found."}), 404
        if profile.get("last_login"):
            profile["last_login"] = profile["last_login"].isoformat()
        return jsonify({"profile": profile}), 200
    except Exception:
        logger.exception("admin_get_profile failed")
        return jsonify({"error": "Could not retrieve profile."}), 500


@app.route("/api/session/logout", methods=["POST"])
@app.route("/api/admin/logout", methods=["POST"])  # old path, kept for pages cached before the update
def session_logout():
    """Release the caller's session immediately (no expiry check needed)."""
    token = _bearer_token()
    if token:
        try:
            with get_connection() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE users
                    SET admin_session_hash = NULL, admin_session_last_active = NULL
                    WHERE admin_session_hash = %s
                    """,
                    (_hash_token(token),),
                )
        except Exception:
            logger.exception("session_logout failed")
            return jsonify({"error": "Could not log out."}), 500
    return jsonify({"message": "Logged out."}), 200


@app.route("/api/admin/users", methods=["GET"])
@require_admin
def admin_get_users():
    try:
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT username, first_name, last_name, last_login, user_type, status
                FROM users
                ORDER BY id ASC
                """
            )
            users = cur.fetchall()
            for u in users:
                if u["last_login"]:
                    u["last_login"] = u["last_login"].isoformat()
        return jsonify({"users": users}), 200
    except Exception:
        logger.exception("admin_get_users failed")
        return jsonify({"error": "Could not retrieve users."}), 500


@app.route("/api/admin/users/<username>/status", methods=["PUT"])
@require_admin
def admin_update_status(username):
    data = request.get_json(silent=True) or {}
    new_status = str(data.get("status", "active")).strip().lower()
    if new_status not in ALLOWED_STATUS_VALUES:
        return jsonify({"error": "Invalid status."}), 400
    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET status = %s, failed_login_attempts = 0
                WHERE username = %s
                """,
                (new_status, username),
            )
            updated = cur.rowcount
        if updated == 0:
            return jsonify({"error": "User not found."}), 404
        return jsonify({"message": "User status updated successfully."}), 200
    except Exception:
        logger.exception("admin_update_status failed")
        return jsonify({"error": "Could not update user status."}), 500


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
