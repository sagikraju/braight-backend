-- brAIght users table
-- Run this once against your Postgres database, e.g.:
--   psql -U postgres -d braight -f schema.sql

CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    first_name    VARCHAR(100) NOT NULL,
    last_name     VARCHAR(100) NOT NULL,
    username      VARCHAR(50)  NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    user_type     VARCHAR(20)  NOT NULL CHECK (user_type IN ('Student', 'Jobseeker', 'ADMIN')),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Speeds up the username lookup that happens on every login attempt.
CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
