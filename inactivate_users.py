"""
brAIght -- daily job: mark users 'inactive' after 60 days without a login.

Run by a Render Cron Job (Command: python inactivate_users.py).
It only calls the inactivate_stale_users() function created by
inactivate_stale_users.sql, so the rule itself lives in the database.

Uses the same database settings as the web service (DATABASE_URL, or
DB_HOST / DB_NAME / DB_USER / DB_PASSWORD ...), so copy those environment
variables to the cron job. Keep this file next to app.py.
"""

import sys

from app import get_connection

INACTIVE_AFTER_DAYS = 60


def main():
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT inactivate_stale_users(%s)", (INACTIVE_AFTER_DAYS,))
        count = cur.fetchone()[0]
    print(f"Inactivated {count} user(s) with no login for {INACTIVE_AFTER_DAYS}+ days.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
