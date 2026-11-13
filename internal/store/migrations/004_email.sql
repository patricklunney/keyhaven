-- Email is required for new accounts and unique (case-insensitive).
-- Existing accounts without one are prompted to add it at their next sign-in,
-- so the column stays nullable for them.
CREATE UNIQUE INDEX users_email_lower_idx ON users (lower(email)) WHERE email IS NOT NULL;
