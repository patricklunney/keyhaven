ALTER TABLE users ADD COLUMN is_admin boolean NOT NULL DEFAULT false;

-- Append-only record of security-relevant events. actor/target are plain text
-- (no foreign keys) so history survives deletion of the user or client.
CREATE TABLE audit_events (
    id          bigserial PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    actor_id    text,
    actor_name  text,
    action      text NOT NULL,
    target_type text,
    target_id   text,
    target_name text,
    details     jsonb NOT NULL DEFAULT '{}',
    ip          text
);
CREATE INDEX audit_events_at_idx ON audit_events (at DESC);
CREATE INDEX audit_events_target_idx ON audit_events (target_type, target_id);
