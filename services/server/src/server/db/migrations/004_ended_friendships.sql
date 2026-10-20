-- A friendship that ended (removed or blocked), kept for a while so either
-- member can still report what was said in it: otherwise the abuser could
-- unfriend first and make the conversation unreportable. Only the retired
-- conversation id and the two members; swept at expires_at, and deleted with
-- either member's account.

CREATE TABLE ended_friendships (
  convo_id   text PRIMARY KEY CHECK (convo_id ~ '^[0-9a-f]{64}$'),
  id_lo      text NOT NULL,
  id_hi      text NOT NULL,
  ended_at   timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  CHECK (id_lo COLLATE "C" < id_hi COLLATE "C")
);
CREATE INDEX ended_friendships_id_lo_idx ON ended_friendships (id_lo);
CREATE INDEX ended_friendships_id_hi_idx ON ended_friendships (id_hi);
CREATE INDEX ended_friendships_expires_at_idx ON ended_friendships (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON ended_friendships TO ${APP_ROLE};
