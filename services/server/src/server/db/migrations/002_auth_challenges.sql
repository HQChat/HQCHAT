-- Sign-in challenges, several open per identity, each under its own random id.
-- A challenge is spent only by the proof that matches it, and each source
-- address keeps its own few, so a stranger who knows a public key can neither
-- replace the owner's open challenge nor spend it with a wrong proof.
-- `source` is a short hash of the caller's address, never the address itself.

DROP TABLE auth_challenges;

CREATE UNLOGGED TABLE auth_challenges (
  id           text NOT NULL,
  challenge_id text NOT NULL CHECK (challenge_id ~ '^[0-9a-f]{32}$'),
  source       text NOT NULL,
  proof        text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  PRIMARY KEY (id, challenge_id)
);
CREATE INDEX auth_challenges_expires_at_idx ON auth_challenges (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON auth_challenges TO ${APP_ROLE};
