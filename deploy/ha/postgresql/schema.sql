-- Same schema the service applies itself when DB_MIGRATE=true.
-- Run as the owner of the "onetime" database on the primary.
CREATE TABLE IF NOT EXISTS messages (
    id          text        PRIMARY KEY,
    message     text        NOT NULL,
    hashed_key  text        NOT NULL,
    encrypted   boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_expires_at_idx ON messages (expires_at);
