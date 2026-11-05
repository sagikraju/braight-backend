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

import datetime
import hashlib
import io
import logging
import os
import re
import json
import secrets
import threading
import urllib.request
from functools import wraps

import psycopg
from flask import Flask, g, jsonify, request, send_file
from flask_cors import CORS
from psycopg import errors as pg_errors
from psycopg.rows import dict_row
from werkzeug.security import check_password_hash, generate_password_hash

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("braight-backend")

app = Flask(__name__)
# Request bodies are capped at 256 KB everywhere except document uploads (see
# DOC_MAX_BYTES below), which may be a little over 5 MB with the form overhead.
SMALL_BODY_LIMIT = 256 * 1024
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024

_origins_env = os.environ.get(
    "ALLOWED_ORIGINS",
    "https://braight.in,https://www.braight.in,https://zesty-palmier-26ddfc.netlify.app"
).strip()
ALLOWED_ORIGINS = [o.strip().rstrip("/") for o in _origins_env.split(",") if o.strip()]
CORS(
    app,
    origins=ALLOWED_ORIGINS,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)

# ADMIN accounts can still log in if already present, but public signup is
# restricted to Student and Jobseeker.
ALLOWED_SIGNUP_TYPES = {"Student", "Jobseeker"}
ALLOWED_STATUS_VALUES = {"active", "inactive", "locked"}
MAX_FAILED_ATTEMPTS = 3

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

            # Login only looks at the status column. Users are set to 'inactive' (after 60 days
            # without a login) by the scheduled database job, not here.
            if not is_admin:
                if status == "locked":
                    return jsonify({"error": "Your account is locked after three unsuccessful login attempts. Please contact the administrator."}), 403
                if status == "inactive":
                    return jsonify({"error": "Your account is inactive because there has been no activity for 60 days. Please contact the administrator."}), 403
                if status != "active":
                    return jsonify({"error": "Your account is not active. Please contact the administrator."}), 403

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


@app.route("/api/admin/active-sessions", methods=["GET"])
@require_admin
def admin_active_sessions():
    """
    Database sessions that are running a query right now (admins only).
    Read-only and fixed: the SQL below is the only thing ever executed here and
    nothing from the request is put into it. Note: PostgreSQL hides the query
    text and some columns of other roles' sessions unless this database user
    has the privileges to see them.
    """
    try:
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT pid, usename Username, datname DBName, client_addr, state, query
                FROM pg_stat_activity
                WHERE state = 'active'
                  AND pid <> pg_backend_pid()
                """
            )
            rows = cur.fetchall()
        for r in rows:
            # client_addr is an inet value (ipaddress object); make it JSON-friendly
            if r.get("client_addr") is not None:
                r["client_addr"] = str(r["client_addr"])
        return jsonify({"sessions": rows}), 200
    except Exception:
        logger.exception("admin_active_sessions failed")
        return jsonify({"error": "Could not retrieve active sessions."}), 500


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


# ==========================================================================
# Program tables: cohorts, enrollments, progress, applications
# (tables are created by 001_program_tables.sql)
# ==========================================================================

COHORT_PROGRAMS = {"student", "jobseeker"}
COHORT_STATUSES = {"planned", "open", "running", "completed", "cancelled"}
ENROLLMENT_STATUSES = {"applied", "accepted", "active", "completed", "dropped", "rejected"}
APPLICATION_KINDS = {"jobseeker", "school", "contact"}
APPLICATION_STATUSES = {"new", "contacted", "accepted", "rejected", "closed"}

APPLICATIONS_MAX_PER_EMAIL_PER_HOUR = 3
APPLICATIONS_MAX_PER_HOUR = 100          # overall flood protection for the public form
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PROGRESS_KEY_RE = re.compile(r"^(milestone|session):([0-9]{1,2})$")


class InputError(ValueError):
    """A problem with the data the client sent (returned as HTTP 400)."""


def _bad_request(exc):
    return jsonify({"error": str(exc)}), 400


def _text(data, key, max_len, required=False, label=None):
    label = label or key
    value = data.get(key)
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise InputError(f"{label} must be text.")
    value = value.strip()
    if not value:
        if required:
            raise InputError(f"{label} is required.")
        return None
    if len(value) > max_len:
        raise InputError(f"{label} must be at most {max_len} characters.")
    return value


def _choice(data, key, allowed, default=None, label=None):
    label = label or key
    value = data.get(key)
    if value is None or value == "":
        if default is not None:
            return default
        raise InputError(f"{label} is required.")
    value = str(value).strip().lower()
    if value not in allowed:
        raise InputError(f"{label} must be one of: {', '.join(sorted(allowed))}.")
    return value


def _date(data, key, label=None):
    label = label or key
    value = data.get(key)
    if value in (None, ""):
        return None
    try:
        return datetime.date.fromisoformat(str(value).strip())
    except ValueError:
        raise InputError(f"{label} must be a date (YYYY-MM-DD).")


def _whole_number(value, label, minimum=1, maximum=None):
    if isinstance(value, bool):
        raise InputError(f"{label} must be a whole number.")
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise InputError(f"{label} must be a whole number.")
    if number < minimum or (maximum is not None and number > maximum):
        limit = f"between {minimum} and {maximum}" if maximum is not None else f"at least {minimum}"
        raise InputError(f"{label} must be {limit}.")
    return number


def _optional_int_arg(name):
    raw = request.args.get(name)
    if raw in (None, ""):
        return None
    return _whole_number(raw, name, minimum=1)


def _optional_choice_arg(name, allowed):
    raw = (request.args.get(name) or "").strip().lower()
    if not raw:
        return None
    if raw not in allowed:
        raise InputError(f"{name} must be one of: {', '.join(sorted(allowed))}.")
    return raw


def _iso(value):
    return value.isoformat() if value is not None else None


def _normalize_type(user_type):
    return (user_type or "").strip().lower().replace(" ", "")


def _claim_progress(cur, user_id, cohort_id):
    """Attach ticks saved before enrollment (no cohort) to the cohort the user has just joined."""
    cur.execute(
        """
        UPDATE progress SET cohort_id = %s
        WHERE user_id = %s AND cohort_id IS NULL
          AND NOT EXISTS (
                SELECT 1 FROM progress p2
                WHERE p2.user_id = progress.user_id
                  AND p2.cohort_id = %s
                  AND p2.item_key = progress.item_key)
        """,
        (cohort_id, user_id, cohort_id),
    )


def _current_cohort(cur, user_id):
    """The cohort a user is currently in (accepted or active), newest first, or None."""
    cur.execute(
        """
        SELECT c.id, c.name, c.program, c.status
        FROM enrollments e
        JOIN cohorts c ON c.id = e.cohort_id
        WHERE e.user_id = %s AND e.status IN ('accepted', 'active')
        ORDER BY e.created_at DESC, e.id DESC
        LIMIT 1
        """,
        (user_id,),
    )
    return cur.fetchone()


# ---------------------------------------------------------------- cohorts --

def _cohort_fields(data):
    program = _choice(data, "program", COHORT_PROGRAMS, label="Program")
    name = _text(data, "name", 150, required=True, label="Name")
    school = _text(data, "school", 200, label="School")
    start_date = _date(data, "start_date", "Start date")
    end_date = _date(data, "end_date", "End date")
    if start_date and end_date and end_date < start_date:
        raise InputError("End date can't be before the start date.")
    sessions_total = _whole_number(data.get("sessions_total", 8), "Sessions", minimum=1, maximum=52)
    status = _choice(data, "status", COHORT_STATUSES, default="planned", label="Status")
    notes = _text(data, "notes", 2000, label="Notes")
    return program, name, school, start_date, end_date, sessions_total, status, notes


@app.route("/api/admin/cohorts", methods=["GET"])
@require_admin
def admin_list_cohorts():
    try:
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT c.id, c.program, c.name, c.school, c.start_date, c.end_date,
                       c.sessions_total, c.status, c.notes,
                       COUNT(e.id) AS enrollment_count
                FROM cohorts c
                LEFT JOIN enrollments e ON e.cohort_id = c.id
                GROUP BY c.id
                ORDER BY c.created_at DESC, c.id DESC
                """
            )
            cohorts = cur.fetchall()
        for c in cohorts:
            c["start_date"] = _iso(c["start_date"])
            c["end_date"] = _iso(c["end_date"])
        return jsonify({"cohorts": cohorts}), 200
    except Exception:
        logger.exception("admin_list_cohorts failed")
        return jsonify({"error": "Could not retrieve cohorts."}), 500


@app.route("/api/admin/cohorts", methods=["POST"])
@require_admin
def admin_create_cohort():
    data = request.get_json(silent=True) or {}
    try:
        fields = _cohort_fields(data)
    except InputError as exc:
        return _bad_request(exc)
    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO cohorts
                    (program, name, school, start_date, end_date, sessions_total, status, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                fields,
            )
            new_id = cur.fetchone()[0]
        return jsonify({"id": new_id, "message": "Cohort created."}), 201
    except pg_errors.UniqueViolation:
        return jsonify({"error": "A cohort with this program, name and school already exists."}), 409
    except Exception:
        logger.exception("admin_create_cohort failed")
        return jsonify({"error": "Could not create the cohort."}), 500


@app.route("/api/admin/cohorts/<int:cohort_id>", methods=["PUT"])
@require_admin
def admin_update_cohort(cohort_id):
    data = request.get_json(silent=True) or {}
    try:
        fields = _cohort_fields(data)
    except InputError as exc:
        return _bad_request(exc)
    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT program FROM cohorts WHERE id = %s FOR UPDATE", (cohort_id,))
            row = cur.fetchone()
            if row is None:
                return jsonify({"error": "Cohort not found."}), 404
            if row[0] != fields[0]:
                cur.execute("SELECT COUNT(*) FROM enrollments WHERE cohort_id = %s", (cohort_id,))
                if cur.fetchone()[0] > 0:
                    return jsonify({"error": "The program can't be changed once users are enrolled."}), 409
            cur.execute(
                """
                UPDATE cohorts
                SET program = %s, name = %s, school = %s, start_date = %s, end_date = %s,
                    sessions_total = %s, status = %s, notes = %s
                WHERE id = %s
                """,
                (*fields, cohort_id),
            )
        return jsonify({"message": "Cohort updated."}), 200
    except pg_errors.UniqueViolation:
        return jsonify({"error": "A cohort with this program, name and school already exists."}), 409
    except Exception:
        logger.exception("admin_update_cohort failed")
        return jsonify({"error": "Could not update the cohort."}), 500


# ------------------------------------------------------------ enrollments --

@app.route("/api/admin/enrollments", methods=["GET"])
@require_admin
def admin_list_enrollments():
    try:
        cohort_id = _optional_int_arg("cohort_id")
        status = _optional_choice_arg("status", ENROLLMENT_STATUSES)
    except InputError as exc:
        return _bad_request(exc)
    try:
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT e.id, e.status, e.notes, e.created_at,
                       u.username, u.first_name, u.last_name, u.user_type,
                       c.id AS cohort_id, c.name AS cohort_name, c.program
                FROM enrollments e
                JOIN users u ON u.id = e.user_id
                JOIN cohorts c ON c.id = e.cohort_id
                WHERE (%s::bigint IS NULL OR e.cohort_id = %s::bigint)
                  AND (%s::text IS NULL OR e.status = %s::text)
                ORDER BY e.created_at DESC, e.id DESC
                LIMIT 1000
                """,
                (cohort_id, cohort_id, status, status),
            )
            rows = cur.fetchall()
        for r in rows:
            r["created_at"] = _iso(r["created_at"])
        return jsonify({"enrollments": rows}), 200
    except Exception:
        logger.exception("admin_list_enrollments failed")
        return jsonify({"error": "Could not retrieve enrollments."}), 500


@app.route("/api/admin/enrollments", methods=["POST"])
@require_admin
def admin_create_enrollment():
    data = request.get_json(silent=True) or {}
    try:
        username = _text(data, "username", 200, required=True, label="Username")
        cohort_id = _whole_number(data.get("cohort_id"), "Cohort")
        status = _choice(data, "status", ENROLLMENT_STATUSES, default="accepted", label="Status")
        notes = _text(data, "notes", 2000, label="Notes")
    except InputError as exc:
        return _bad_request(exc)
    try:
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id, user_type FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            if user is None:
                return jsonify({"error": "User not found."}), 404
            kind = _normalize_type(user["user_type"])
            if kind == "admin":
                return jsonify({"error": "Administrators can't be enrolled in a cohort."}), 400

            cur.execute("SELECT id, program, status FROM cohorts WHERE id = %s", (cohort_id,))
            cohort = cur.fetchone()
            if cohort is None:
                return jsonify({"error": "Cohort not found."}), 404
            if cohort["status"] == "cancelled":
                return jsonify({"error": "This cohort is cancelled."}), 400
            if kind != cohort["program"]:
                return jsonify({"error": f"This user is a {user['user_type']} and can't join a {cohort['program']} cohort."}), 400

            cur.execute(
                """
                INSERT INTO enrollments (user_id, cohort_id, status, notes)
                VALUES (%s, %s, %s, %s)
                RETURNING id
                """,
                (user["id"], cohort_id, status, notes),
            )
            new_id = cur.fetchone()["id"]
            if status in ("accepted", "active"):
                _claim_progress(cur, user["id"], cohort_id)
        return jsonify({"id": new_id, "message": "User enrolled."}), 201
    except pg_errors.UniqueViolation:
        return jsonify({"error": "This user is already enrolled in that cohort."}), 409
    except Exception:
        logger.exception("admin_create_enrollment failed")
        return jsonify({"error": "Could not enroll the user."}), 500


@app.route("/api/admin/enrollments/<int:enrollment_id>", methods=["PUT"])
@require_admin
def admin_update_enrollment(enrollment_id):
    data = request.get_json(silent=True) or {}
    try:
        status = _choice(data, "status", ENROLLMENT_STATUSES, label="Status")
        notes = _text(data, "notes", 2000, label="Notes")
    except InputError as exc:
        return _bad_request(exc)
    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE enrollments SET status = %s, notes = %s
                WHERE id = %s
                RETURNING user_id, cohort_id
                """,
                (status, notes, enrollment_id),
            )
            row = cur.fetchone()
            if row is None:
                return jsonify({"error": "Enrollment not found."}), 404
            if status in ("accepted", "active"):
                _claim_progress(cur, row[0], row[1])
        return jsonify({"message": "Enrollment updated."}), 200
    except Exception:
        logger.exception("admin_update_enrollment failed")
        return jsonify({"error": "Could not update the enrollment."}), 500


# --------------------------------------------------------------- progress --

@app.route("/api/progress", methods=["GET"])
@require_session
def get_my_progress():
    """The logged-in user's own ticks (for their current cohort, or none)."""
    try:
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id FROM users WHERE username = %s", (g.session_username,))
            user = cur.fetchone()
            if user is None:
                return jsonify({"error": "User not found."}), 404
            cohort = _current_cohort(cur, user["id"])
            cohort_id = cohort["id"] if cohort else None
            cur.execute(
                """
                SELECT item_key FROM progress
                WHERE user_id = %s AND COALESCE(cohort_id, 0) = COALESCE(%s::bigint, 0)
                """,
                (user["id"], cohort_id),
            )
            items = [r["item_key"] for r in cur.fetchall()]
        cohort_out = None
        if cohort:
            cohort_out = {"name": cohort["name"], "program": cohort["program"], "status": cohort["status"]}
        return jsonify({"items": items, "cohort": cohort_out}), 200
    except Exception:
        logger.exception("get_my_progress failed")
        return jsonify({"error": "Could not load your progress."}), 500


@app.route("/api/progress", methods=["PUT"])
@require_session
def set_my_progress():
    """Tick or un-tick one item for the logged-in user."""
    data = request.get_json(silent=True) or {}
    item_key = str(data.get("item_key") or "").strip()
    done = data.get("done")
    match = _PROGRESS_KEY_RE.match(item_key)
    if not match or not isinstance(done, bool):
        return jsonify({"error": "item_key and done are required."}), 400
    number = int(match.group(2))
    limit = 20 if match.group(1) == "milestone" else 52
    if number < 1 or number > limit:
        return jsonify({"error": "Unknown item."}), 400
    try:
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id FROM users WHERE username = %s", (g.session_username,))
            user = cur.fetchone()
            if user is None:
                return jsonify({"error": "User not found."}), 404
            cohort = _current_cohort(cur, user["id"])
            cohort_id = cohort["id"] if cohort else None
            if done:
                cur.execute(
                    """
                    INSERT INTO progress (user_id, cohort_id, item_key)
                    VALUES (%s, %s, %s)
                    ON CONFLICT DO NOTHING
                    """,
                    (user["id"], cohort_id, item_key),
                )
            else:
                cur.execute(
                    """
                    DELETE FROM progress
                    WHERE user_id = %s AND COALESCE(cohort_id, 0) = COALESCE(%s::bigint, 0)
                      AND item_key = %s
                    """,
                    (user["id"], cohort_id, item_key),
                )
        return jsonify({"ok": True}), 200
    except Exception:
        logger.exception("set_my_progress failed")
        return jsonify({"error": "Could not save your progress."}), 500


@app.route("/api/admin/progress", methods=["GET"])
@require_admin
def admin_progress_overview():
    """
    Completion per user for one cohort (?cohort_id=12) or for users who have
    ticks but no cohort (?cohort_id=none).
    """
    raw = (request.args.get("cohort_id") or "").strip().lower()
    try:
        cohort_id = None if raw == "none" else _whole_number(raw, "cohort_id")
    except InputError as exc:
        return _bad_request(exc)
    try:
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cohort = None
            if cohort_id is None:
                cur.execute(
                    """
                    SELECT u.username, u.first_name, u.last_name, u.user_type,
                           NULL::text AS enrollment_status,
                           COUNT(p.id) FILTER (WHERE split_part(p.item_key, ':', 1) = 'milestone') AS milestones_done,
                           COUNT(p.id) FILTER (WHERE split_part(p.item_key, ':', 1) = 'session') AS sessions_done,
                           MAX(p.completed_at) AS last_activity
                    FROM progress p
                    JOIN users u ON u.id = p.user_id
                    WHERE p.cohort_id IS NULL
                    GROUP BY u.id, u.username, u.first_name, u.last_name, u.user_type
                    ORDER BY u.first_name, u.last_name, u.username
                    """
                )
            else:
                cur.execute(
                    "SELECT id, name, program, sessions_total, status FROM cohorts WHERE id = %s",
                    (cohort_id,),
                )
                cohort = cur.fetchone()
                if cohort is None:
                    return jsonify({"error": "Cohort not found."}), 404
                cur.execute(
                    """
                    SELECT u.username, u.first_name, u.last_name, u.user_type,
                           en.status AS enrollment_status,
                           COUNT(p.id) FILTER (WHERE split_part(p.item_key, ':', 1) = 'milestone') AS milestones_done,
                           COUNT(p.id) FILTER (WHERE split_part(p.item_key, ':', 1) = 'session') AS sessions_done,
                           MAX(p.completed_at) AS last_activity
                    FROM enrollments en
                    JOIN users u ON u.id = en.user_id
                    LEFT JOIN progress p ON p.user_id = en.user_id AND p.cohort_id = en.cohort_id
                    WHERE en.cohort_id = %s AND en.status IN ('accepted', 'active', 'completed')
                    GROUP BY u.id, u.username, u.first_name, u.last_name, u.user_type, en.status
                    ORDER BY u.first_name, u.last_name, u.username
                    """,
                    (cohort_id,),
                )
            rows = cur.fetchall()
        for r in rows:
            r["last_activity"] = _iso(r["last_activity"])
        return jsonify({"cohort": cohort, "rows": rows}), 200
    except Exception:
        logger.exception("admin_progress_overview failed")
        return jsonify({"error": "Could not retrieve progress."}), 500


# ----------------------------------------------------------- applications --

@app.route("/api/public/cohorts", methods=["GET"])
def public_open_cohorts():
    """Jobseeker cohorts that are open for applications (no login needed; no personal data)."""
    try:
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT id, name, start_date
                FROM cohorts
                WHERE program = 'jobseeker' AND status = 'open'
                ORDER BY start_date NULLS LAST, id
                """
            )
            cohorts = cur.fetchall()
        for c in cohorts:
            c["start_date"] = _iso(c["start_date"])
        return jsonify({"cohorts": cohorts}), 200
    except Exception:
        logger.exception("public_open_cohorts failed")
        return jsonify({"error": "Could not retrieve cohorts."}), 500


@app.route("/api/applications", methods=["POST"])
def submit_application():
    """Public form: freshers application, school enquiry or general message."""
    data = request.get_json(silent=True) or {}

    # Spam trap: a hidden field that real visitors never fill in. Pretend it worked.
    if str(data.get("website") or "").strip():
        return jsonify({"message": "Thank you. We have received your message."}), 201

    try:
        kind = _choice(data, "kind", APPLICATION_KINDS, label="Type")
        full_name = _text(data, "full_name", 200, required=True, label="Name")
        email = _text(data, "email", 320, required=True, label="Email")
        if not _EMAIL_RE.match(email):
            raise InputError("Please enter a valid email address.")
        phone = _text(data, "phone", 40, label="Phone")
        organization = _text(data, "organization", 200, required=(kind == "school"),
                             label="School name" if kind == "school" else "Organization")
        city = _text(data, "city", 100, label="City")
        message = _text(data, "message", 5000, required=(kind == "contact"), label="Message")
        if data.get("consent") is not True:
            raise InputError("Please tick the box to agree to be contacted.")
        cohort_id = None
        if kind == "jobseeker" and data.get("cohort_id") not in (None, ""):
            cohort_id = _whole_number(data.get("cohort_id"), "Cohort")
    except InputError as exc:
        return _bad_request(exc)

    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM applications WHERE created_at > NOW() - INTERVAL '1 hour'")
            if cur.fetchone()[0] >= APPLICATIONS_MAX_PER_HOUR:
                return jsonify({"error": "We are receiving a lot of messages right now. Please try again later."}), 429
            cur.execute(
                """
                SELECT COUNT(*) FROM applications
                WHERE LOWER(email) = LOWER(%s) AND created_at > NOW() - INTERVAL '1 hour'
                """,
                (email,),
            )
            if cur.fetchone()[0] >= APPLICATIONS_MAX_PER_EMAIL_PER_HOUR:
                return jsonify({"error": "You have already sent a few messages recently. Please wait a while before sending another."}), 429
            if cohort_id is not None:
                cur.execute(
                    "SELECT 1 FROM cohorts WHERE id = %s AND program = 'jobseeker' AND status = 'open'",
                    (cohort_id,),
                )
                if cur.fetchone() is None:
                    return jsonify({"error": "That cohort is not open for applications."}), 400
            cur.execute(
                """
                INSERT INTO applications
                    (kind, full_name, email, phone, organization, city, message, cohort_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (kind, full_name, email, phone, organization, city, message, cohort_id),
            )
        return jsonify({"message": "Thank you. We have received your message and will get back to you soon."}), 201
    except Exception:
        logger.exception("submit_application failed")
        return jsonify({"error": "Could not send your message. Please try again."}), 500


@app.route("/api/admin/applications", methods=["GET"])
@require_admin
def admin_list_applications():
    try:
        status = _optional_choice_arg("status", APPLICATION_STATUSES)
        kind = _optional_choice_arg("kind", APPLICATION_KINDS)
    except InputError as exc:
        return _bad_request(exc)
    try:
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT a.id, a.kind, a.full_name, a.email, a.phone, a.organization, a.city,
                       a.message, a.status, a.admin_notes, a.created_at,
                       a.cohort_id, c.name AS cohort_name
                FROM applications a
                LEFT JOIN cohorts c ON c.id = a.cohort_id
                WHERE (%s::text IS NULL OR a.status = %s::text)
                  AND (%s::text IS NULL OR a.kind = %s::text)
                ORDER BY a.created_at DESC, a.id DESC
                LIMIT 500
                """,
                (status, status, kind, kind),
            )
            rows = cur.fetchall()
            cur.execute("SELECT status, COUNT(*) AS n FROM applications GROUP BY status")
            counts = {r["status"]: r["n"] for r in cur.fetchall()}
        for r in rows:
            r["created_at"] = _iso(r["created_at"])
        return jsonify({"applications": rows, "counts": counts}), 200
    except Exception:
        logger.exception("admin_list_applications failed")
        return jsonify({"error": "Could not retrieve applications."}), 500


@app.route("/api/admin/applications/<int:application_id>", methods=["PUT"])
@require_admin
def admin_update_application(application_id):
    data = request.get_json(silent=True) or {}
    try:
        status = _choice(data, "status", APPLICATION_STATUSES, label="Status")
        admin_notes = _text(data, "admin_notes", 5000, label="Notes")
    except InputError as exc:
        return _bad_request(exc)
    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE applications SET status = %s, admin_notes = %s WHERE id = %s",
                (status, admin_notes, application_id),
            )
            if cur.rowcount == 0:
                return jsonify({"error": "Application not found."}), 404
        return jsonify({"message": "Application updated."}), 200
    except Exception:
        logger.exception("admin_update_application failed")
        return jsonify({"error": "Could not update the application."}), 500


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


# --------------------------------------------------------------------------
# Forgot password: one-time reset link sent to the email on the account
# --------------------------------------------------------------------------
#
# Flow: Login page popup -> POST /api/forgot-password {username}
#       -> email with a link to SetPassword.html#token=...
#       -> SetPassword page -> POST /api/reset-password {token, newPassword}
#
# The link carries a random token; only its SHA-256 hash is stored, it expires
# after RESET_TOKEN_MINUTES and works once. The reply to the popup is always the
# same, whether or not the username exists, so it can't be used to find out who
# has an account. Mail goes out through an HTTPS email API (Resend), because
# Render's free web services block outgoing SMTP.
#
# Environment variables (Render -> Environment):
#   RESEND_API_KEY   API key from resend.com                      (required)
#   MAIL_FROM        e.g. "brAIght <no-reply@braight.in>"         (required; the domain must be verified in Resend)
#   SITE_URL         e.g. https://braight.in                      (default https://braight.in)

RESET_TOKEN_MINUTES = 30
RESET_COOLDOWN_SECONDS = 60       # at most one email per account per minute
RESET_MAX_PER_HOUR = 5            # ... and five per hour
RESET_MAX_PER_HOUR_ALL = 200      # overall ceiling, so the endpoint can't be used to flood the mail account
FORGOT_REPLY = {
    "message": "If that username exists and has an email address on file, "
               "we have sent a password reset link to it. The link works for "
               f"{RESET_TOKEN_MINUTES} minutes."
}


def _site_url():
    return os.environ.get("SITE_URL", "https://braight.in").strip().rstrip("/")


def _send_email(to_address, subject, text_body, html_body):
    """Send one email through Resend. Returns True on success, never raises."""
    api_key = os.environ.get("RESEND_API_KEY", "").strip()
    sender = os.environ.get("MAIL_FROM", "").strip()
    if not api_key or not sender:
        logger.error("Email not sent: RESEND_API_KEY and MAIL_FROM must be set.")
        return False
    payload = json.dumps({
        "from": sender,
        "to": [to_address],
        "subject": subject,
        "text": text_body,
        "html": html_body,
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=payload,
        method="POST",
        headers={
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json",
            "User-Agent": "braight-backend/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception:
        logger.exception("sending the reset email failed")
        return False


def _send_reset_email(to_address, first_name, token):
    link = _site_url() + "/SetPassword.html#token=" + token
    name = (first_name or "there").strip() or "there"
    text_body = (
        f"Hello {name},\n\n"
        "We received a request to reset your brAIght password. Open this link to choose a new one:\n\n"
        f"{link}\n\n"
        f"The link works once and expires in {RESET_TOKEN_MINUTES} minutes. "
        "If you did not ask for this, you can ignore this email; your password stays the same.\n\n"
        "brAIght"
    )
    safe_name = (name.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    html_body = (
        f"<p>Hello {safe_name},</p>"
        "<p>We received a request to reset your brAIght password. "
        "Click the button to choose a new one:</p>"
        f'<p><a href="{link}" style="display:inline-block;background:#C89B5C;color:#17324F;'
        'font-weight:700;text-decoration:none;padding:12px 22px;border-radius:8px">Reset password</a></p>'
        f'<p>Or copy this link into your browser:<br><a href="{link}">{link}</a></p>'
        f"<p>The link works once and expires in {RESET_TOKEN_MINUTES} minutes. "
        "If you did not ask for this, you can ignore this email; your password stays the same.</p>"
        "<p>brAIght</p>"
    )
    _send_email(to_address, "Reset your brAIght password", text_body, html_body)


@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    username = username.strip() if isinstance(username, str) else ""
    if not username or len(username) > 100:
        return jsonify({"error": "Please enter your username."}), 400

    job = None   # (email, first_name, token) to mail after the database work is done
    try:
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT id, first_name, email FROM users WHERE username = %s",
                (username,),
            )
            user = cur.fetchone()
            email = ((user or {}).get("email") or "").strip()
            if user and "@" in email:
                cur.execute(
                    """
                    SELECT
                      COUNT(*) FILTER (WHERE user_id = %s
                                       AND created_at > NOW() - make_interval(secs => %s)) AS recent,
                      COUNT(*) FILTER (WHERE user_id = %s) AS user_hour,
                      COUNT(*) AS all_hour
                    FROM password_resets
                    WHERE created_at > NOW() - INTERVAL '1 hour'
                    """,
                    (user["id"], RESET_COOLDOWN_SECONDS, user["id"]),
                )
                counts = cur.fetchone()
                if (counts["recent"] == 0
                        and counts["user_hour"] < RESET_MAX_PER_HOUR
                        and counts["all_hour"] < RESET_MAX_PER_HOUR_ALL):
                    token = secrets.token_urlsafe(32)
                    cur.execute(
                        """
                        INSERT INTO password_resets (user_id, token_hash, expires_at)
                        VALUES (%s, %s, NOW() + make_interval(mins => %s))
                        """,
                        (user["id"], _hash_token(token), RESET_TOKEN_MINUTES),
                    )
                    job = (email, user["first_name"], token)
    except Exception:
        logger.exception("forgot-password failed")
        return jsonify({"error": "Could not process the request. Please try again."}), 500

    if job:
        # Sent in the background so the reply takes the same time whether or not
        # the username exists.
        threading.Thread(target=_send_reset_email, args=job, daemon=True).start()
    return jsonify(FORGOT_REPLY), 200


@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json(silent=True) or {}
    token = data.get("token")
    new_password = data.get("newPassword")
    if not isinstance(token, str) or not token.strip() or len(token) > 200:
        return jsonify({"error": "This reset link is not valid."}), 400
    if not isinstance(new_password, str) or len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    if len(new_password) > 200:
        return jsonify({"error": "Password is too long."}), 400

    try:
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            # Claim the token atomically: a second use (or a race) finds nothing.
            cur.execute(
                """
                UPDATE password_resets
                   SET used_at = NOW()
                 WHERE token_hash = %s AND used_at IS NULL AND expires_at > NOW()
                RETURNING user_id
                """,
                (_hash_token(token.strip()),),
            )
            row = cur.fetchone()
            if row is None:
                return jsonify({
                    "error": "This reset link is invalid or has expired. Please request a new one."
                }), 400
            # New password; also end any live session so whoever had the old password is out.
            cur.execute(
                """
                UPDATE users
                   SET password_hash = %s,
                       admin_session_hash = NULL,
                       admin_session_last_active = NULL
                 WHERE id = %s
                """,
                (generate_password_hash(new_password), row["user_id"]),
            )
            # Any other links still outstanding for this user stop working.
            cur.execute(
                "UPDATE password_resets SET used_at = NOW() WHERE user_id = %s AND used_at IS NULL",
                (row["user_id"],),
            )
    except Exception:
        logger.exception("reset-password failed")
        return jsonify({"error": "Could not reset the password. Please try again."}), 500
    return jsonify({"message": "Password updated. You can now log in."}), 200


# --------------------------------------------------------------------------
# My Payments (subscribed flag) and My Documents
# --------------------------------------------------------------------------

@app.before_request
def _limit_body_size():
    """Everything except the document upload only accepts small bodies."""
    if request.method in ("POST", "PUT") and request.path != "/api/documents":
        length = request.content_length
        if length is not None and length > SMALL_BODY_LIMIT:
            return jsonify({"error": "Request too large."}), 413


@app.errorhandler(413)
def _too_large(_exc):
    return jsonify({"error": "That file is too large. The limit is 5 MB."}), 413


@app.route("/api/subscribe", methods=["POST"])
@require_session
def subscribe():
    """Called when a user opens My Payments: marks the account as subscribed."""
    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute("UPDATE users SET subscribed = TRUE WHERE username = %s", (g.session_username,))
        return jsonify({"subscribed": True}), 200
    except Exception:
        logger.exception("subscribe failed")
        return jsonify({"error": "Could not update your subscription."}), 500


DOC_MAX_BYTES = 5 * 1024 * 1024          # per file
DOC_MAX_FILES = 20                       # per user
DOC_MAX_TOTAL_BYTES = 40 * 1024 * 1024   # per user, all files together
DOC_CATEGORIES = {"resume", "certificate", "id_proof", "other"}
_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
_JPEG_OK = lambda b: b.startswith(b"\xff\xd8\xff")
# extension -> (content type we serve it as, check that the bytes really are that kind of file)
DOC_TYPES = {
    "pdf":  ("application/pdf", lambda b: b.startswith(b"%PDF-")),
    "png":  ("image/png", lambda b: b.startswith(b"\x89PNG\r\n\x1a\n")),
    "jpg":  ("image/jpeg", _JPEG_OK),
    "jpeg": ("image/jpeg", _JPEG_OK),
    "docx": (_DOCX, lambda b: b.startswith(b"PK\x03\x04")),
}
# Only these are ever shown inside the browser; everything else downloads.
DOC_INLINE_TYPES = {"application/pdf", "image/png", "image/jpeg"}


def require_subscribed(view):
    """Document endpoints are for subscribed users only (users.subscribed = TRUE).
    Use below @require_session. Anyone else gets 403 with code NOT_SUBSCRIBED."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        try:
            with get_connection() as conn, conn.cursor() as cur:
                cur.execute("SELECT subscribed FROM users WHERE username = %s", (g.session_username,))
                row = cur.fetchone()
        except Exception:
            logger.exception("subscription check failed")
            return jsonify({"error": "Could not check your subscription."}), 500
        if not row or row[0] is not True:
            return jsonify({
                "error": "You cannot view/upload documents currently. Please upgrade to premium to upload/view your documents.",
                "code": "NOT_SUBSCRIBED",
            }), 403
        return view(*args, **kwargs)
    return wrapper


def _clean_filename(raw):
    name = (raw or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(ch for ch in name if ch.isprintable() and ch not in '<>:"|?*').strip(" .")
    if len(name) > 200:
        stem, dot, ext = name.rpartition(".")
        name = (stem[: 200 - len(ext) - 1] + "." + ext) if dot else name[:200]
    return name


def _doc_view(row):
    return {
        "id": row["id"],
        "filename": row["filename"],
        "category": row["category"],
        "size": row["size_bytes"],
        "contentType": row["content_type"],
        "inline": row["content_type"] in DOC_INLINE_TYPES,
        "uploadedAt": _iso(row["uploaded_at"]),
    }


@app.route("/api/documents", methods=["GET"])
@require_session
@require_subscribed
def list_documents():
    try:
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT d.id, d.filename, d.category, d.size_bytes, d.content_type, d.uploaded_at
                FROM user_documents d JOIN users u ON u.id = d.user_id
                WHERE u.username = %s
                ORDER BY d.uploaded_at DESC, d.id DESC
                """,
                (g.session_username,),
            )
            rows = cur.fetchall()
        return jsonify({
            "documents": [_doc_view(r) for r in rows],
            "limits": {"maxBytes": DOC_MAX_BYTES, "maxFiles": DOC_MAX_FILES},
        }), 200
    except Exception:
        logger.exception("list_documents failed")
        return jsonify({"error": "Could not load your documents."}), 500


@app.route("/api/documents", methods=["POST"])
@require_session
@require_subscribed
def upload_document():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return jsonify({"error": "Please choose a file."}), 400
    name = _clean_filename(upload.filename)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    spec = DOC_TYPES.get(ext)
    if not name or spec is None:
        return jsonify({"error": "Only PDF, PNG, JPG and DOCX files can be uploaded."}), 400
    category = (request.form.get("category") or "other").strip()
    if category not in DOC_CATEGORIES:
        return jsonify({"error": "Please choose a valid document type."}), 400

    data = upload.read(DOC_MAX_BYTES + 1)
    if not data:
        return jsonify({"error": "That file is empty."}), 400
    if len(data) > DOC_MAX_BYTES:
        return jsonify({"error": "That file is too large. The limit is 5 MB."}), 413
    content_type, looks_right = spec
    if not looks_right(data):
        return jsonify({"error": "That file does not look like a real ." + ext + " file."}), 400

    try:
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            # Lock the user's row so two simultaneous uploads can't both slip past the limits.
            cur.execute("SELECT id FROM users WHERE username = %s FOR UPDATE", (g.session_username,))
            user = cur.fetchone()
            if user is None:
                return jsonify({"error": "Authentication required.", "code": "AUTH_REQUIRED"}), 401
            cur.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(size_bytes), 0) AS total FROM user_documents WHERE user_id = %s",
                (user["id"],),
            )
            used = cur.fetchone()
            if used["n"] >= DOC_MAX_FILES:
                return jsonify({"error": f"You can keep up to {DOC_MAX_FILES} documents. Delete one to upload another."}), 409
            if used["total"] + len(data) > DOC_MAX_TOTAL_BYTES:
                return jsonify({"error": "You have reached your storage limit. Delete a document to upload another."}), 409
            cur.execute(
                """
                INSERT INTO user_documents (user_id, filename, content_type, category, size_bytes, data)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id, filename, category, size_bytes, content_type, uploaded_at
                """,
                (user["id"], name, content_type, category, len(data), data),
            )
            row = cur.fetchone()
        return jsonify({"document": _doc_view(row)}), 201
    except Exception:
        logger.exception("upload_document failed")
        return jsonify({"error": "Could not save the document."}), 500


@app.route("/api/documents/<int:doc_id>/file", methods=["GET"])
@require_session
@require_subscribed
def get_document_file(doc_id):
    """Returns the file to its owner only. ?download=1 forces a download."""
    try:
        with get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT d.filename, d.content_type, d.data
                FROM user_documents d JOIN users u ON u.id = d.user_id
                WHERE d.id = %s AND u.username = %s
                """,
                (doc_id, g.session_username),
            )
            row = cur.fetchone()
    except Exception:
        logger.exception("get_document_file failed")
        return jsonify({"error": "Could not load the document."}), 500
    if row is None:
        return jsonify({"error": "Document not found."}), 404

    as_download = request.args.get("download") == "1" or row["content_type"] not in DOC_INLINE_TYPES
    resp = send_file(
        io.BytesIO(bytes(row["data"])),
        mimetype=row["content_type"],
        as_attachment=as_download,
        download_name=row["filename"],
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "private, no-store"
    resp.headers["Content-Security-Policy"] = "sandbox; default-src 'none'"
    return resp


@app.route("/api/documents/<int:doc_id>", methods=["DELETE"])
@require_session
@require_subscribed
def delete_document(doc_id):
    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM user_documents
                WHERE id = %s AND user_id = (SELECT id FROM users WHERE username = %s)
                """,
                (doc_id, g.session_username),
            )
            if cur.rowcount == 0:
                return jsonify({"error": "Document not found."}), 404
        return jsonify({"message": "Document deleted."}), 200
    except Exception:
        logger.exception("delete_document failed")
        return jsonify({"error": "Could not delete the document."}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=False)
