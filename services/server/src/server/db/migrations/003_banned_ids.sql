-- Identities an operator banned. The account itself is deleted; this row is
-- what keeps its key from signing straight back in to the same id. It holds
-- the id only (sha256 of the public key), never the key or a reason.

CREATE TABLE banned_ids (
  id        text PRIMARY KEY CHECK (id ~ '^[0-9a-f]{64}$'),
  banned_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON banned_ids TO ${APP_ROLE};
