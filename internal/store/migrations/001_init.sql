CREATE TABLE users (
    id           text PRIMARY KEY,
    handle       bytea NOT NULL UNIQUE,          -- WebAuthn user handle (random, opaque)
    username     text NOT NULL,
    display_name text NOT NULL,
    email        text,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_username_lower_idx ON users (lower(username));

CREATE TABLE credentials (
    id           bytea PRIMARY KEY,              -- WebAuthn credential ID
    user_id      text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         text NOT NULL,
    data         jsonb NOT NULL,                 -- serialized webauthn.Credential
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);
CREATE INDEX credentials_user_id_idx ON credentials (user_id);

CREATE TABLE sessions (
    token_hash bytea PRIMARY KEY,
    user_id    text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE clients (
    id                        text PRIMARY KEY,
    name                      text NOT NULL,
    secret_hash               bytea,             -- NULL for public (PKCE-only) clients
    redirect_uris             text[] NOT NULL,
    post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',
    created_at                timestamptz NOT NULL DEFAULT now()
);

-- Short-lived, single-use or expiring records: WebAuthn ceremonies, pending
-- authorization requests, authorization codes and refresh tokens. Keys are
-- stored hashed so a database read does not reveal usable values.
CREATE TABLE ephemeral (
    kind       text NOT NULL,
    key_hash   bytea NOT NULL,
    user_id    text REFERENCES users(id) ON DELETE CASCADE,
    data       jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (kind, key_hash)
);
CREATE INDEX ephemeral_expires_at_idx ON ephemeral (expires_at);
CREATE INDEX ephemeral_user_id_idx ON ephemeral (user_id) WHERE user_id IS NOT NULL;
